// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the GNU General Public License Version 2 found in the ebpf/LICENSE file
// or at:
//     https://opensource.org/license/gpl-2-0

struct ufrag {
	// +1 for ':' separator in ICE username
	uint8_t u8[MAX_UFRAG_LEN + 1];
};

/* STUN header 64 bits: 2 0s, 14 type, 14 length, 2 0s, 32 magic cookie */
#define STUN_HDR_LEN 8

#define STUN_TX_ID_LEN 12

/* Attributes on 32-bit boundaries, 4 bytes: (2 type, 2 length) or 4 value */
#define STUN_ATTR_BOUND 4

struct attr_scratch {
	/* currently processing pkt attribute buf. */
	uint8_t buf[STUN_ATTR_BOUND];
	/* complete ufrag value */
	struct ufrag ufrag;
	size_t ufrag_len;

	uint8_t round;
	uint32_t next_index;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__uint(value_size, sizeof(struct attr_scratch));
	__uint(max_entries, 1);
} percpu_attr_scratch_map SEC(".maps");

static void *percpu_attr_scratch_page()
{
	int key = 0;
	void *value = bpf_map_lookup_elem(&percpu_attr_scratch_map, &key);
	if (value != NULL) {
		memset(value, 0, sizeof(struct attr_scratch));
	}
	return value;
}

struct _parse_attr_ctx {
	struct sk_reuseport_md *md;
	struct attr_scratch *scratch;
};

static int _do_parse_attr_loop(uint32_t index, void *_ctx)
{
	struct _parse_attr_ctx *c = _ctx;
	struct attr_scratch *s = c->scratch;
	int offset = 8 + STUN_HDR_LEN + STUN_TX_ID_LEN +
		     index * STUN_ATTR_BOUND; /* UDP hdr + STUN hdr */
	uint8_t *pkt = c->md->data + offset;
	uint8_t *pkt_end = c->md->data_end;

	/* Workaround against ebpf limitation where we can't
	 * arbitrarily move index variable forward*/
	if (index < s->next_index)
		return LOOP_CONTINUE;

	if (index >= MAX_INSTR)
		return LOOP_BREAK;

	if (pkt + STUN_ATTR_BOUND > pkt_end) {
		/* Non-linear packet */
		int r = bpf_skb_load_bytes(c->md, offset, s->buf, STUN_ATTR_BOUND);
		if (r != 0)
			return LOOP_BREAK;
		pkt = &s->buf[0];
	}

	/* Copy ufrag if we are in the middle of it */
	if (s->ufrag_len != 0) {
		uint32_t round_offset = s->round * STUN_ATTR_BOUND;

		if (round_offset > MAX_UFRAG_LEN - STUN_ATTR_BOUND)
			return LOOP_BREAK;
		if (round_offset > s->ufrag_len - STUN_ATTR_BOUND)
			return LOOP_BREAK;

		memcpy(&s->ufrag.u8[round_offset], &pkt[0], STUN_ATTR_BOUND);

		// Check the presence of ':' separator
		if (s->ufrag.u8[round_offset] == ':') {
			s->ufrag_len = round_offset;
			return LOOP_BREAK;
		} else if (s->ufrag.u8[round_offset + 1] == ':') {
			s->ufrag_len = round_offset + 1;
			return LOOP_BREAK;
		} else if (s->ufrag.u8[round_offset + 2] == ':') {
			s->ufrag_len = round_offset + 2;
			return LOOP_BREAK;
		} else if (s->ufrag.u8[round_offset + 3] == ':') {
			s->ufrag_len = round_offset + 3;
			return LOOP_BREAK;
		}

		s->round++;
		return LOOP_CONTINUE;
	}

	uint16_t attr_type = pkt[0] << 8 | pkt[1];
	uint16_t attr_len = pkt[2] << 8 | pkt[3];

	if (attr_type == 0x0006) {
		/* USERNAME attr */
		s->ufrag_len = attr_len;
		s->round = 0;
		return LOOP_CONTINUE;
	}

	/* Advance to next attribute */
	s->next_index = index + 1 + attr_len / 4 + ((attr_len % 4) ? 1 : 0);
	return LOOP_CONTINUE;
}

static int parse_ice(struct sk_reuseport_md *md, struct ufrag *ufrag,
		     size_t *ufrag_len_ptr)
{
	if (ufrag == NULL || ufrag_len_ptr == NULL)
		return IERR_SANITY;

	uint8_t _stun_hdr[STUN_HDR_LEN];

	uint8_t *pkt = md->data;
	uint8_t *pkt_end = md->data_end;
	/* Advance UDP header */
	pkt += 8;

	if (md->len < 8 + STUN_HDR_LEN) {
		/* Could be a very short non-STUN packet. */
		return IERR_OK;
	}

	if (pkt + STUN_HDR_LEN > pkt_end) {
		/* Non-linear packet */
		int r = bpf_skb_load_bytes(md, 8, _stun_hdr, STUN_HDR_LEN);
		if (r != 0)
			return IERR_LOAD;
		pkt = &_stun_hdr[0];
		pkt_end = &_stun_hdr[STUN_HDR_LEN];
	}

	/* Fast path - check for STUN existence as fast as possible */

	/* Most and least significant 2 bits of every STUN header MUST be zeroes
	 */
	int is_stun_msg = ((pkt[0] & 0xC0) == 0) && ((pkt[3] & 0x03) == 0);
	if (!is_stun_msg)
		return IERR_OK;

	/* STUN magic cookie at offset 4 */
	uint8_t *magic_cookie = pkt + 4;
	is_stun_msg = !memcmp(magic_cookie, "\x21\x12\xa4\x42", 4);
	if (!is_stun_msg)
		return IERR_OK;

	/* Not so fast path. Extract ufrag. */
	uint16_t stun_msg_len = pkt[2] << 8 | pkt[3];
	/* Advance STUN header */
	pkt += STUN_HDR_LEN + STUN_TX_ID_LEN;

	if (md->len < 8 + STUN_HDR_LEN + STUN_TX_ID_LEN + stun_msg_len) {
		/* Packet too short */
		return IERR_SANITY;
	}

	struct attr_scratch *scratch = percpu_attr_scratch_page();
	if (scratch == NULL) {
		return IERR_SANITY;
	}

	struct _parse_attr_ctx ctx = {.md = md, .scratch = scratch};
	bpf_loop((stun_msg_len / STUN_ATTR_BOUND) +
			 ((stun_msg_len % STUN_ATTR_BOUND) ? 1 : 0),
		 _do_parse_attr_loop, &ctx, 0);

	if (scratch->ufrag_len > MAX_UFRAG_LEN) {
		/* ufrag too long */
		return IERR_SANITY;
	}
	/* Ignore ufrag_len, force MAX */
	memcpy(ufrag, &scratch->ufrag, MAX_UFRAG_LEN);

	size_t i;
	for (i = scratch->ufrag_len; i < MAX_UFRAG_LEN; i++) {
		ufrag->u8[i] = 0;
		asm volatile("" ::: "memory");
	}

	*ufrag_len_ptr = scratch->ufrag_len;

	return IERR_OK;
}
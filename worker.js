// DoH Cloudflare Worker: block mediaffic.ir & mediaad.org (returns 0.0.0.0 for A queries)

const BLOCKED = [
  // MediaAd
  "mediaad.org",
  "s1.mediaad.org",

  // Mediaffic (tapsell-like CDN)
  "mediaffic.ir",
  "cdn.mediaffic.ir",

  // Yektanet
  "yektanet.com",
  "cdn.yektanet.com",
  "script.cdn.yektanet.com",

  // ADEXO
  "adexofiles.ir",
  "panel.adexo.ir",

  // Tavoos Ads
  "d1-tavoos.ir",
  "tavoos.ir",
  "tavoos.net",
  "ads.tavoos.net",

  // Najva Push
  "najva.com",
  "push.najva.com",
  "api.najva.com",
  "cdn.najva.com"
];

const UPSTREAM = "https://1.1.1.1/dns-query"; // Cloudflare resolver

// helper: base64url -> ArrayBuffer
function base64urlToArrayBuffer(b64u) {
  // replace base64url chars, pad
  b64u = b64u.replace(/-/g, '+').replace(/_/g, '/');
  while (b64u.length % 4) b64u += '=';
  const bin = atob(b64u);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

// extract qname from a DNS wire-format packet (ArrayBuffer) - returns lowercase string without trailing dot
function extractQName(buf) {
  const view = new Uint8Array(buf);
  // basic check
  if (view.length < 12) return "";
  let pos = 12; // header is 12 bytes
  const labels = [];
  while (pos < view.length) {
    const len = view[pos++];
    if (len === 0) break;
    if ((len & 0xC0) === 0xC0) {
      // pointer (compression) - read pointer and decode from there
      const b2 = view[pos++];
      const pointer = ((len & 0x3F) << 8) | b2;
      // recursively decode pointer
      let p = pointer;
      const labs = [];
      while (p < view.length) {
        const l = view[p++];
        if (l === 0) break;
        if ((l & 0xC0) === 0xC0) { // nested pointer
          const b2n = view[p++];
          p = ((l & 0x3F) << 8) | b2n;
          continue;
        }
        labs.push(String.fromCharCode(...view.slice(p, p + l)));
        p += l;
      }
      labels.push(labs.join(''));
      break;
    } else {
      labels.push(String.fromCharCode(...view.slice(pos, pos + len)));
      pos += len;
    }
  }
  const domain = labels.join('.').toLowerCase();
  return domain.replace(/\.$/, '');
}

// build a DNS response with one A record 0.0.0.0
// requestBuf: Uint8Array (original query) - we will copy ID and question section
function buildAZeroResponse(requestBuf) {
  // parse qdcount to copy question area length
  const req = requestBuf;
  const id0 = req[0], id1 = req[1];

  // find end of question (skip header then qname)
  let pos = 12;
  while (pos < req.length) {
    const len = req[pos++];
    if (len === 0) break;
    // pointer in query shouldn't happen, but just in case
    if ((len & 0xC0) === 0xC0) { pos++; break; }
    pos += len;
  }
  pos += 1; // past the zero byte
  // now pos points to QTYPE (2 bytes) and QCLASS (2 bytes) -> question end at pos+4
  const qEnd = pos + 4;
  // build response:
  // header (2 bytes ID) + flags (2 bytes) + QDCOUNT (2) + ANCOUNT (2) + NSCOUNT (2) + ARCOUNT (2)
  // We'll create: ID (from request), FLAGS = 0x8180 (standard response, no error), QDCOUNT = copied, ANCOUNT = 1
  const qdcount = (req[4] << 8) | req[5];

  // build header (12 bytes)
  const header = new Uint8Array(12);
  header[0] = id0; header[1] = id1;
  header[2] = 0x81; header[3] = 0x80; // QR=1, Opcode=0, AA=0, TC=0, RD=1|RA=1 -> 0x8180 is common
  header[4] = req[4]; header[5] = req[5]; // QDCOUNT
  header[6] = 0x00; header[7] = 0x01; // ANCOUNT = 1
  header[8] = 0x00; header[9] = 0x00; // NSCOUNT = 0
  header[10] = 0x00; header[11] = 0x00; // ARCOUNT = 0

  // question section: copy from request from byte 12 to qEnd (inclusive of qtype/class)
  const question = req.slice(12, qEnd);

  // answer section:
  // NAME: pointer to offset 12 -> 0xc0 0x0c
  // TYPE A (0x0001), CLASS IN (0x0001), TTL (0x0000003C = 60s), RDLENGTH (0x0004), RDATA (0x00 00 00 00)
  const answer = new Uint8Array(2 + 2 + 2 + 4 + 2 + 4);
  let w = 0;
  answer[w++] = 0xC0; answer[w++] = 0x0C; // name pointer
  answer[w++] = 0x00; answer[w++] = 0x01; // type A
  answer[w++] = 0x00; answer[w++] = 0x01; // class IN
  answer[w++] = 0x00; answer[w++] = 0x00; answer[w++] = 0x00; answer[w++] = 0x3C; // TTL = 60
  answer[w++] = 0x00; answer[w++] = 0x04; // RDLENGTH = 4
  answer[w++] = 0x00; answer[w++] = 0x00; answer[w++] = 0x00; answer[w++] = 0x00; // 0.0.0.0

  // concatenate header + question + answer
  const out = new Uint8Array(header.length + question.length + answer.length);
  out.set(header, 0);
  out.set(question, header.length);
  out.set(answer, header.length + question.length);
  return out.buffer;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Only handle /dns-query path (standard DoH)
    if (!url.pathname.startsWith("/dns-query")) {
      return new Response("Cloudflare DoH Worker", { status: 200 });
    }

    // Get DNS packet ArrayBuffer:
    let dnsBuf;
    if (request.method === "POST") {
      // content-type should be application/dns-message
      dnsBuf = await request.arrayBuffer();
    } else if (request.method === "GET") {
      // look for ?dns=<base64url>
      const b64 = url.searchParams.get("dns");
      if (!b64) {
        return new Response("Missing dns param", { status: 400 });
      }
      dnsBuf = base64urlToArrayBuffer(b64);
    } else {
      return new Response("Method not allowed", { status: 405 });
    }

    // extract queried domain
    let qname = "";
    try {
      qname = extractQName(dnsBuf);
    } catch (e) {
      qname = "";
    }

    // check blocked list (substring match)
    const qlower = qname.toLowerCase();
    const blocked = BLOCKED.some(b => qlower.endsWith(b) || qlower.includes("." + b));
    if (blocked) {
      // return A => 0.0.0.0
      const respBuf = buildAZeroResponse(new Uint8Array(dnsBuf));
      return new Response(respBuf, {
        status: 200,
        headers: { "Content-Type": "application/dns-message" }
      });
    }

    // else forward to upstream resolver (Cloudflare)
    // forward the original packet as POST
    const upstreamRes = await fetch(UPSTREAM, {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: dnsBuf
    });

    const body = await upstreamRes.arrayBuffer();
    return new Response(body, {
      status: 200,
      headers: { "Content-Type": "application/dns-message" }
    });
  }
};

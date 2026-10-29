# Seed origin: `relay_feed_url`

Every seed here is a URL written in the generator from the documented
`https://host[:port]` form (RFC 3986 §3.2). Host names are `example`
names (RFC 2606) and private addresses; none comes from a deployment of
any product (fuzz/README.md, seed origin rule).

Regenerate (from `fuzz/`; function `feed_url_seeds`):

```sh
cargo run --example gen_seeds_m3 -- corpus
```

| Seed | Content |
|------|---------|
| `wu14-feed-url-name-port.bin` | `https://server.example.gov:8443` |
| `wu14-feed-url-ipv4.bin` | `https://10.0.0.1` |
| `wu14-feed-url-ipv6.bin` | `https://[fd00::1]:443/` |
| `wu14-feed-url-digits.bin` | `https://123.45` (all digits; refused) |
| `wu14-feed-url-http.bin` | `http://` (refused) |
| `wu14-feed-url-port-0.bin` | port 0 (refused) |

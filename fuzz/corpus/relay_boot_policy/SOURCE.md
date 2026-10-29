# Seed origin: `relay_boot_policy`

Every seed here is a short script written in the generator in the format
of `fuzz_targets/relay_boot_policy.rs`. The scripts name lists that the
target itself builds and signs at start-up with a key it generates
(`usgp-crypto`); no list, key or certificate is stored in a seed, and
none comes from a server, captured traffic or any deployment of another
product (fuzz/README.md, seed origin rule).

Lists (index: generation, kind): 0: 1; 1: 1, other content; 2: 2; 3: 3;
4: 2, other content; 5: 10; 6: another boot service; 7: signed by another
key; 8: wrong payload type; 9: schema 2; 10: payload names another key;
11: a MAC listed twice.

Regenerate (from `fuzz/`; function `boot_policy_seeds`):

```sh
cargo run --example gen_seeds_m3 -- corpus
```

| Seed | Script |
|------|--------|
| `wu14-feed-in-order.bin` | lists 0, 2, 3, 5 (four new generations) |
| `wu14-feed-rollback.bin` | 2 then 0 (rollback) |
| `wu14-feed-reuse-unchanged.bin` | 0, 1 (reused generation), 0 (unchanged) |
| `wu14-feed-refusals.bin` | 6 to 11 (each refused; gate stays awaiting), then 0 |
| `wu14-feed-cache-then-server.bin` | 0 from the cache, 2, 2 from the cache (unchanged) |
| `wu14-feed-same-generation-other-list.bin` | 2 then 4 (reused generation) |
| `wu14-feed-flip.bin` | 0, list 2 with a bit flipped at offset 64, then 2 |
| `wu14-feed-raw.bin` | the bytes `{}` as an envelope, then 0 |

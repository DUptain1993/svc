# svc — crypto stealer + polymorphic crypter

Rust workspace: per-target crypto wallet stealer (`svc-payload`) plus a per-build polymorphic wrapper (`svc-crypter`). Every wrapper differs in ISA permutation, gate chain, decrypt scheme, execution method, integrity check, junk shape, and per-build secrets.

## workspace layout

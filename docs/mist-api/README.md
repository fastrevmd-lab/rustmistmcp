# Vendored Mist OpenAPI snapshot

`mist-openapi.json` is the official Mist OpenAPI 3.1 document, vendored from
[`mistsys/mist_openapi`](https://github.com/mistsys/mist_openapi) commit
`feeb569a409dcc5119c4d8935c99cc46d482d770`. It is Mist API version
`2609.1.0` and has SHA-256
`22f55432535ab38f6c0539392a729b8fd515a9ccae9df693fbd4ff23d40b8fac`.

The original source URL is
<https://raw.githubusercontent.com/mistsys/mist_openapi/master/mist.openapi.json>.
The upstream document is MIT licensed; its license is preserved verbatim in
[`LICENSE`](LICENSE). Do not edit the snapshot by hand. Regenerate
`catalog.json` and `parity.json` with:

```sh
python3 scripts/generate-mist-catalog.py
```

The generator verifies the locked source hash and API/OpenAPI versions before
writing canonical JSON. `catalog.json` is the richer runtime catalog;
`parity.json` is the schema-conformant operation-to-tool parity manifest.

`operation-policy.json` is the reviewed, source-locked table that supplies
one exact six-way authorization action and one verification policy for every
operation key. `frozen-reference-inventory.json` is the deterministic audit
input for the reference surface: parity maps only its 1,047 current wrappers,
while missing operations, the stale wrappers, and JSON-only multipart gaps are
explicit expiring exceptions. These policy and inventory inputs are part of
the generator contract; do not regenerate or edit either by inference.

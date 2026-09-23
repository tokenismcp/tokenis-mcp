# @tokenis/crypto

TypeScript/JavaScript SDK for [Tokenis](https://github.com/tokenismcp/tokenis-mcp):
additively homomorphic EC-ElGamal over secp256k1 and the no-key delegation
protocol, compiled to WebAssembly from the same Rust core as the Python SDK.
Keys, ciphertexts and masked values are byte-compatible across both.

Requires Node 20+.

## Encryption

```ts
import { keygen, encrypt, Decryptor, Ciphertext } from "@tokenis/crypto";

const { privateKey, publicKey } = keygen();

// Add under encryption; plaintexts are bigint (signed 64-bit).
const total = encrypt(publicKey, 1200n).add(encrypt(publicKey, 34n)).mul(2n);

const decryptor = new Decryptor(privateKey); // range [-2^24, 2^24] by default
decryptor.decrypt(total); // 2468n

// Wire format shared with the Python SDK.
const bytes = total.toBytes();
const again = Ciphertext.fromBytesWithKey(bytes, publicKey);
```

## No-key delegation

Let an untrusted server compute on your data without ever seeing it or
holding a key:

```ts
import { Owner, evaluateAffineMasked, combineMultiplication } from "@tokenis/crypto";

const owner = new Owner();

// Affine functions: the server sees only uniformly random masked values.
const f = { coefficients: [3n, -2n], intercept: 5n };
const { masked, correction } = owner.delegateAffine(f, [100n, 7n]);
const serverResult = evaluateAffineMasked(f, masked); // runs on the server
owner.unblindAffine(serverResult, correction); // 291n

// Products, via a Beaver triple (one round trip).
const triple = owner.prepareTriple();
const opening = owner.openMultiplication(12n, 34n, triple); // send to server
const eg = combineMultiplication(opening); // runs on the server
owner.reconstructMultiplication(triple, opening, eg); // 408n
```

Masks, corrections and triples are one-time: using one twice throws, as does
using one with a different `Owner`.

## Security notes

- Secrets live in WebAssembly memory, are zeroed when freed, and are freed
  when their handle is garbage-collected (call `.free()` to do it
  immediately). `PrivateKey.exportSecretBytes()` is the one deliberate way a
  secret becomes JavaScript memory.
- Randomness comes from `crypto.getRandomValues`.
- Every byte string parsed (`fromBytes`) is validated; malformed input
  throws rather than being accepted.
- Ciphertext-times-ciphertext multiplication is not offered; see the
  repository's `tokenis/crypto/ec_fhe.py` for why.

License: Apache-2.0.

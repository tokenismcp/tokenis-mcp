<img src="https://raw.githubusercontent.com/tokenismcp/tokenis-mcp/main/assets/logo.png" width="96" alt="Tokenis logo">

# tokenis-core

The cryptographic core of [Tokenis](https://github.com/tokenismcp/tokenis-mcp):
additively homomorphic EC-ElGamal over secp256k1 and the no-key delegation
protocol (one-time-pad masking plus Beaver-triple multiplication). It is the
single implementation behind the Tokenis Python SDK (PyO3) and TypeScript SDK
(WebAssembly).

```rust
use tokenis_core::elgamal::{Decryptor, PrivateKey, add, encrypt};

let sk = PrivateKey::generate()?;
let pk = sk.public_key();
let total = add(&encrypt(&pk, 1200)?, &encrypt(&pk, 34)?)?;
assert_eq!(Decryptor::new(&sk, 1 << 24)?.decrypt(&total)?, 1234);
# Ok::<(), tokenis_core::Error>(())
```

Security properties, and what they do *not* cover, are listed in the crate
documentation (`src/lib.rs`). This crate has not been independently audited;
its elliptic-curve arithmetic is RustCrypto's `k256`, which has.

License: Apache-2.0.

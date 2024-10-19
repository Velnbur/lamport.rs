# `lamport.rs`

 Simple Rust implementaion of Lamport commitment scheme.
 
## Examples
 
```rust
use lamport::SecretKey;
use rand::thread_rng;

let msg = b"Hello, world!";

// Generate random secret key
let seckey = SecretKey::generate(&mut thread_rng());

// Derive public key from it
let pubkey = seckey.public_key();

// Sign the message
let signature = seckey.sign(&msg);

// Verify the key using public one.
pubkey.verify(&signature, msg);
```

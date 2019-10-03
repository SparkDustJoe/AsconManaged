# AsconManaged
A C++/CLI implementation of the ASCON AEAD encryption scheme (v1.2) from the CAESAR and NIST Lightweight Crypto Competitions

Includes the following "flavors" of ASCON:

- 160 (aka "Ascon80pq", 64-bit rate, 160-bit key, 128-bit nonce)
- 128 (64-bit rate, 128-bit key, 128-bit nonce)
- 128a (128-bit rate, 128-bit key, 128-bit nonce, recommended)
- Hash (64-bit rate, unkeyed, no personalization or salt, 256-bit message digest)
- Xof (the only different between Hash and Xof are the starting constants within the state)

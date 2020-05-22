# nano-key-exchange

Performs a key exchange with nano keys, which produces a shared key that only
the two participants will know.

Contains one function, `nano_get_shared_key`, which takes 3 arguments:
- A constant pointer to the 32 byte private key (not a seed, not expanded)
- A constant pointer to the 32 byte public key of the other party
- A mutable pointer to a 32 byte output buffer for the shared key

It returns a uint8_t which is currently either 0, indicating success, or 1,
indicating a bad public key. On failure, the output buffer isn't modified.

```c
uint8_t nano_get_shared_key(
    const uint8_t * secret_key,
    const uint8_t * other_public_key,
    uint8_t * shared_key_out
);
```

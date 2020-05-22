#ifndef NANO_KEY_EXCHANGE_H
#define NANO_KEY_EXCHANGE_H

uint8_t nano_get_shared_key(
    const uint8_t * secret_key,
    const uint8_t * other_public_key,
    uint8_t * shared_key_out
);

#endif

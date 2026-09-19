#include "crypto_hash_sha512.h"

// open.c normally gets this helper from sign.c, which ESPHome's reduced
// libsodium manifest does not compile. Keep this definition identical to the
// pinned libsodium source; the prehash domain is unused by detached v1 checks
// but is required for the included translation unit to link correctly.
void _crypto_sign_ed25519_ref10_hinit(crypto_hash_sha512_state *state, int prehashed) {
  static const unsigned char dom2_prefix[34] = {
      'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ', 'n', 'o', ' ', 'E', 'd', '2',
      '5', '5', '1', '9', ' ', 'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0};
  crypto_hash_sha512_init(state);
  if (prehashed)
    crypto_hash_sha512_update(state, dom2_prefix, sizeof(dom2_prefix));
}

// Compile the missing sources from the pinned package instead of introducing a
// second libsodium component, which conflicts with ESPHome's noise-c package.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "crypto_hash/sha512/cp/hash_sha512_cp.c"
#include "crypto_sign/ed25519/ref10/open.c"
#pragma GCC diagnostic pop

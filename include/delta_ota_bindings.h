/* Pulls esp_delta_ota into the generated bindings.
 *
 * esp-idf-sys generates bindings from a curated header list that covers the
 * well-known components -- esp_websocket_client is in it, esp_delta_ota is
 * not. An extra component is built either way; without a `bindings_header`
 * its symbols simply never reach Rust.
 */
#include "esp_delta_ota.h"

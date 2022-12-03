#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
  *output_length = 4 * ((input_length + 2) / 3);

  char *encoded_data = malloc(*output_length);
  if (encoded_data == NULL) return NULL;

  for (size_t i = 0, j = 0; i < input_length;) {
    uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

    encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
  }

  for (int i = 0; i < *output_length; i++) {
    if (i % 76 == 0) {
      if (i != 0) encoded_data[i++] = '\n';
    }
  }

  return encoded_data;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s <string>\n", argv[0]);
    return 1;
  }

  const char *plaintext = argv[1];
  size_t output_length;

  char *encoded = base64_encode((const unsigned char *)plaintext, strlen(plaintext), &output_length);

  printf("Base64-encoded version: %s\n", encoded);

  free(encoded);

  return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// SHA256 constants
static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Rotate right function
uint32_t ROTR(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

// Shift right function
uint32_t SHR(uint32_t x, int n)
{
    return x >> n;
}

// Functions used in the SHA256 algorithm
#define Ch(x, y, z)  (z ^ (x & (y ^ z)))
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#define e0(x)        (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define e1(x)        (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)        (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)        (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// Function to hash a message using SHA256
void sha256(char* input, char* output)
{
    // Hash values
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
             h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    // Message schedule (expanded message)
    uint32_t s[64];

    // Working variables
    uint32_t a, b, c, d, e, f, g, h;

    // Temporary variables
    uint32_t t1, t2;

    // Number of bytes in the message
    int msg_len = strlen(input);

    // Number of bits in the message
    int msg_bit_len = msg_len * 8;

    // The message must be padded to an even multiple of 512 bits
    int padding = 64 - ((msg_bit_len + 1 + 64) % 512) / 8;
    if (padding < 1)
        padding += 64;

    // Allocate an array to hold the padded message
    char* msg = malloc(msg_len + padding + 8);

    // Copy the original message to the padded array
    memcpy(msg, input, msg_len);

    // Append a single '1' bit to the message
    msg[msg_len] = 0x80;

    // Append '0' bits to the message until it is a multiple of 512 bits
    for (int i = msg_len + 1; i < msg_len + padding; i++)
        msg[i] = 0x00;

    // Append the length of the original message (before padding) as a 64-bit integer
    for (int i = 0; i < 8; i++)
        msg[msg_len + padding + i] = (msg_bit_len >> (56 - 8 * i)) & 0xff;

    // Process the message in successive 512-bit chunks
    for (int i = 0; i < msg_len + padding + 8; i += 64)
    {
        // Break chunk into sixteen 32-bit words
        for (int j = 0; j < 64; j++)
            s[j] = (msg[i + j * 4 + 0] << 24) | (msg[i + j * 4 + 1] << 16) | (msg[i + j * 4 + 2] << 8) | (msg[i + j * 4 + 3]);

        // Initialize hash value for this chunk
        a = h0; b = h1; c = h2; d = h3; e = h4; f = h5; g = h6; h = h7;

        // Main loop
        for (int j = 0; j < 64; j++)
        {
            t1 = h + e1(e) + Ch(e, f, g) + K[j] + s[j];
            t2 = e0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Add this chunk's hash to the result
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Clean up and return the resulting hash
    free(msg);

    sprintf(output, "%x%x%x%x%x%x%x%x", h0, h1, h2, h3, h4, h5, h6, h7);
}

int main(int argc, char** argv)
{
    // Check if the correct number of arguments was provided
    if (argc != 3)
    {
        printf("Usage: sha256decoder <hash> <dictionary>\n");
        return 1;
    }

    // Get the hash value and dictionary file from the command line arguments
    char* hash = argv[1];
    char* dict_file = argv[2];

    // Open the dictionary file
    FILE* dict = fopen(dict_file, "r");
    if (dict == NULL)
    {
        printf("Error: unable to open dictionary file '%s'\n", dict_file);
        return 1;
    }

    // Read the dictionary file line by line
    char line[256];
    while (fgets(line, sizeof(line), dict) != NULL)
    {
        // Remove the newline character from the end of the line
        line[strcspn(line, "\n")] = 0;

        // Calculate the SHA256 hash of the line
        char hash_buf[65];
        sha256(line, hash_buf);

        // Check if the hash matches the expected value
        // Check if the hash matches the expected value
        if (strcmp(hash_buf, hash) == 0)
        {
            printf("Match found: '%s'\n", line);
            return 0;
        }
    }

    printf("No match found in dictionary\n");
    fclose(dict);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void decode(const char *s)
{
    // Make a copy of the input string
    char *str = strdup(s);

    // Ensure that the input string is a multiple of 4
    int num_pads = 0;
    int n = strlen(str);
    if (n % 4 != 0)
    {
        num_pads = 4 - n % 4;
        for (int i = 0; i < num_pads; i++)
        {
            str[n + i] = '=';
        }
        str[n + num_pads] = '\0';
    }

    // Decode the base64 string
    for (int i = 0, j = 0; i < n + num_pads; i += 4, j += 3)
    {
        // Decode 4 bytes at a time
        char a[4], b[4];
        for (int k = 0; k < 4; k++)
        {
            a[k] = str[i + k];
            if (a[k] == '=')
            {
                b[k] = 0;
            }
            else
            {
                b[k] = strchr(b64, a[k]) - b64;
            }
        }

        // Convert the decoded bytes to characters
        char c[3];
        c[0] = (b[0] << 2) | (b[1] >> 4);
        c[1] = (b[1] << 4) | (b[2] >> 2);
        c[2] = (b[2] << 6) | b[3];

        // Print the characters to the output
        for (int k = 0; k < 3 - num_pads; k++)
        {
            putchar(c[k]);
        }
    }

    // Free the memory used for the copy of the string
    free(str);
}

int main(int argc, char *argv[])
{
    // Ensure that a base64 encoded string was provided as a command line argument
    if (argc != 2)
    {
        printf("Usage: %s <base64 encoded string>\n", argv[0]);
        return 1;
    }

    // Decode the base64 encoded string
    decode(argv[1]);
    putchar('\n');

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"

struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];

const char *version = "0.1.211009";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

const char *formats[3] = {"publickey","rmd160","address"};
const char *looks[2] = {"compress","uncompress"};

void set_hash160(char *param, uint8_t *hash160);
void generate_address(uint8_t *hash160, char *address);

uint8_t hash160[20]; // Hash160 value

int main(int argc, char **argv) {
    if(argc < 4) {
        printf("Missing parameters\n");
        exit(0);
    }
    
    switch(strlen(argv[1])) {
        case 40: // Assuming Hash160 values are 40 characters long
            set_hash160(argv[1], hash160);
            break;
        default:
            printf("Unknown hash160 length\n");
            exit(0);
            break;
    }
    
    // Operations using Hash160 values
    // Modify as needed
    
    char address[41];
    generate_address(hash160, address);
    printf("Address: %s\n", address);
}

void set_hash160(char *param, uint8_t *hash160) {
    // Convert the hexadecimal string representation of Hash160 to byte array
    for(int i = 0; i < 20; i++) {
        sscanf(param + 2 * i, "%2hhx", &hash160[i]);
    }
}

void generate_address(uint8_t *hash160, char *address) {
    // Generate a Bitcoin address from the Hash160 value
    
    // Step 1: Prepend the version byte (e.g., 0x00 for Mainnet)
    uint8_t version_byte = 0x00;
    
    // Step 2: Concatenate the version byte and the Hash160 value
    uint8_t extended_hash160[21];
    extended_hash160[0] = version_byte;
    memcpy(extended_hash160 + 1, hash160, 20);
    
    // Step 3: Perform double SHA-256 hash of the extended Hash160 value
    uint8_t double_hash[32];
    sha256_Raw(extended_hash160, 21, double_hash);
    sha256_Raw(double_hash, 32, double_hash);
    
    // Step 4: Take the first 4 bytes of the double hash as a checksum
    uint8_t checksum[4];
    memcpy(checksum, double_hash, 4);
    
    // Step 5: Append the checksum to the extended Hash160 value
    uint8_t extended_hash160_checksum[25];
    memcpy(extended_hash160_checksum, extended_hash160, 21);
    memcpy(extended_hash160_checksum + 21, checksum, 4);
    
    // Step 6: Base58 encode the extended Hash160 value with checksum to get the Bitcoin address
    size_t address_len = 41;
    b58enc(address, &address_len, extended_hash160_checksum, 25);
}

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

const char *formats[3] = {"publickey", "rmd160", "address"};
const char *looks[2] = {"compress", "uncompress"};

void set_publickey(char *param, struct Point *publickey);
void generate_strpublickey(struct Point *publickey, bool compress, char *dst);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);

char *str_output = NULL;
char *str_input = NULL;
char *str_publickey_ptr = NULL;

char str_publickey[132];
char str_rmd160[41];
char str_address[41];

struct Point A, B, C;

int FLAG_NUMBER = 0;

mpz_t inversemultiplier, number;

// Minimum public key limit (in hexadecimal string format)
const char *minimum_pubkey_limit = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // Replace with your desired limit

int main(int argc, char **argv) {
    char buffer_input[1024];
    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    mpz_init_set_ui(A.x, 0);
    mpz_init_set_ui(A.y, 0);

    mpz_init_set_ui(B.x, 0);
    mpz_init_set_ui(B.y, 0);

    mpz_init_set_ui(C.x, 0);
    mpz_init_set_ui(C.y, 0);

    mpz_init(number);
    mpz_init(inversemultiplier);

    if (argc < 4) {
        printf("Missing parameters\n");
        exit(0);
    }

    switch (strlen(argv[1])) {
        case 66:
        case 130:
            set_publickey(argv[1], &A);
            break;
        default:
            printf("Unknown publickey length\n");
            exit(0);
            break;
    }

    switch (strlen(argv[3])) {
        case 6

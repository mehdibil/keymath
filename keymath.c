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

// ... (unchanged code)

const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

// ... (unchanged code)

int main(int argc, char **argv)  {
    // ... (unchanged code)

    mpz_init_set_ui(A.x, 0);
    mpz_init_set_ui(A.y, 0);

    mpz_init_set_ui(B.x, 0);
    mpz_init_set_ui(B.y, 0);

    mpz_init_set_ui(C.x, 0);
    mpz_init_set_ui(C.y, 0);

    mpz_init(number);
    mpz_init(inversemultiplier);

    // ... (unchanged code)

    switch (argv[2][0]) {
        case '+':
            if (FLAG_NUMBER) {
                Scalar_Multiplication(G, &B, number);
            }
            Point_Addition(&A, &B, &C);

            // Ensure that the result is greater than or equal to the constant public key
            if (mpz_cmp(C.x, G.x) < 0) {
                mpz_set(C.x, G.x);
            }
            if (mpz_cmp(C.y, G.y) < 0) {
                mpz_set(C.y, G.y);
            }

            break;
        case '-':
            if (FLAG_NUMBER) {
                Scalar_Multiplication(G, &B, number);
            }
            Point_Negation(&B, &C);
            mpz_set(B.x, C.x);
            mpz_set(B.y, C.y);
            Point_Addition(&A, &B, &C);

            // Ensure that the result is greater than or equal to the constant public key
            if (mpz_cmp(C.x, G.x) < 0) {
                mpz_set(C.x, G.x);
            }
            if (mpz_cmp(C.y, G.y) < 0) {
                mpz_set(C.y, G.y);
            }

            break;
        // ... (unchanged code)
    }

    generate_strpublickey(&C, true, str_publickey);
    printf("Result: %s\n\n", str_publickey);
}


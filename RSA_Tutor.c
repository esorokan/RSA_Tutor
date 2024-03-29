#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* convertFromASCII(char* hexString);
char* convertToASCII(char* plaintext);
void generatePrime(mpz_t prime);
char* getInput();
void phiOfN(mpz_t p, mpz_t q, mpz_t phiN);

typedef struct rsaCtx{
  mpz_t p, q, n, phiN, e, d, pt, ct;
}rsaCtx;

void clearCtx(rsaCtx* ctx);
char* decrypt(rsaCtx *ctx, char* encString);
char* encrypt(rsaCtx *ctx, char* hexString);
void initCtx(rsaCtx* ctx);
void printKeys(rsaCtx* ctx);

int main(){
  printf("================================================================\n"
	 "|                     Welcome to RSA Tutor                     |\n"
	 "|                                                              |\n"
	 "|            Follow along to see how this beautifly            |\n"
	 "|                  simple cryptosystem works                   |\n"
	 "|                                                              |\n"
	 "|                        - sorocan534                          |\n"
	 "================================================================\n"
	 );
  //Create rsaCtx struct and needed varaibles
  char enter;
  rsaCtx ctx;
  //Initialize variables and generate their values for RSA
  initCtx(&ctx);
  gmp_printf("First, RSA keys are generated. Two prime numbers, P and Q, are chosen\n"
             "so that their product will be a desired size. For this example a 4096\n"
             "bit key size is desired so p and q will be at least 2048 bits in size.\n"
             "P and Q are:\nP: %ZX\nQ: %ZX\n", ctx.p, ctx.q);
  printf("Enter to continue...");
  scanf("%c", &enter);
  gmp_printf("\nThe resulting product is known as N and will be used as the modulus in\n"
             "the modular exponentiation used in encryption and decryption.\n"
             "Its value is:\nN: %ZX\n", ctx.n);
  printf("Enter to continue...");
  scanf("%c", &enter);
  gmp_printf("\nAfter this, Eulers totient function, phi, is applied to N to find\n"
             "phi(N). This value is needed to find the private key value, D.\n"
             "Eulers totient function counts positive integers up to a number which\n"
             "are coprime with that number. Since our number N is the product of two\n"
             "primes and the totient function is multiplicative, phi(N) is equal to\n"
             "the product of (p-1) and (q-1). phi(p*q) = phi(p)*phi(q) = (p-1)*(q-1)\n"
             "phi(N): %ZX\n", ctx.phiN);
  printf("Enter to continue...");
  scanf("%c", &enter);
  gmp_printf("\nAn exponent value E is also chosen. It must be a positive integer which\n"
             "is coprime with phi(N). A small prime number is commonly chosen for E.\n"
             "E: %Zd (base 10)\n", ctx.e);
  printf("Enter to continue...");
  scanf("%c", &enter);
  gmp_printf("\nNow the final value needed is D. This value is the modular\n"
             "multiplicative inverse of E modulo phi(N). In normal terms this means\n"
             "the value which if multiplied by E and divided by phi(N), the remainer\n"
             "will equal 1; (E*D) mod phi(N)=1.\n"
             "This value can be caculated with the Extended Euclidean Algorithm.\n"
             "For our example the value of D is:\n"
             "D: %ZX\n",ctx.d);
  printf("Enter to continue...");
  scanf("%c", &enter);
  printf("\nTo simmarize. We took two large primes, p and q, mutiplied them to get N\n"
         "We calculated the totient of N and chose an expoent E.\n"
         "Finally we calulated D, the modular mutiplicative inverse of E mod phi(N)\n"
         "The public key is (e, n) and the private key is (d, n).\n"
         "We will now see how they are used.\n");
  printf("Enter to continue...");
  scanf("%c", &enter);
  char* input = getInput();
  char* hexStringIn = convertToASCII(input);
  char* encrypted = encrypt(&ctx, hexStringIn);
  gmp_printf("\nThis is the numerical form of your plaintext: %ZX. It has been\n"
             "converted to ASCII values.\n", ctx.pt);
  printf("Enter to continue...");
  scanf("%c", &enter);
  gmp_printf("\nTo encrypt this is a simple operation. The plaintext number is raised\n"
             "to the power of E. Then mod of N is taken from that number.\n"
             "The result is the encrypted ciphertext.\n"
             "Ciphertext: %ZX\n", ctx.ct);
  printf("Enter to continue...");
  scanf("%c", &enter);
  char* hexStringOut = decrypt(&ctx, encrypted);
  printf("\nTo decrypt is just as easy. Take the ciphertext and raise it to the\n"
         "power of D. Then mod of N is taken from that number.\n"
         "The result is the decrypted plaintext number!\n"
         "Plaintext Number: %s\n", hexStringOut);
  printf("Enter to continue...");
  scanf("%c", &enter);
  char* output = convertFromASCII(hexStringOut);
  printf("\nAfter decoding the ASCII values you get your original message.\n"
         "Plaintext: %s\n", output);
  //Free memory from variables
  free(input);
  free(hexStringIn);
  free(encrypted);
  free(hexStringOut);
  free(output);
  clearCtx(&ctx);
}

void clearCtx(rsaCtx* ctx){
  mpz_clears(ctx->p,
             ctx->q,
             ctx->n,
             ctx->phiN,
             ctx->e,
             ctx->d,
             ctx->pt,
             ctx->ct,
             NULL);
}

//Converts a string of ASCII values to their respective characters to return as a string
char* convertFromASCII(char* hexString){
  char* output = (char*) malloc(strlen(hexString)/2+1);
  if(output == NULL){
    printf("Error allocating memory. Exiting...\n");
    exit(EXIT_FAILURE);
  }
    output[strlen(hexString)/2] = '\0';
  char* end = NULL;
  char buf[] = {'g','g','\0'};
  for(size_t i=0;i<strlen(hexString)/2;i++){
    strncpy(buf, hexString+2*i, 2);
    output[i] = (char) strtol(buf, &end, 16);
    if(output[i] == '\0'){
      printf("Final conversion error. Exiting...\n");
      exit(EXIT_FAILURE);
    }
  }
  output[strlen(hexString)/2] = '\0';
  return output;
}

//Converts a string of text to a string of that texts ASCII values to return
char* convertToASCII(char* plaintext){
  char* hexString = (char*) malloc(2*strlen(plaintext)+1);
  if(hexString == NULL){
    printf("Error allocating memory. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  for(size_t i=0;i<strlen(plaintext);i++){
    sprintf(hexString+2*i, "%X", plaintext[i]);
  }
  hexString[2*strlen(plaintext)] = '\0';
  return hexString;
}

//Decrypts a decimal number string to a string of ASCII values to return
char* decrypt(rsaCtx* ctx, char* encString){
  if(mpz_set_str(ctx->ct, encString, 16) == -1){
    printf("Error converting string to mpz_t. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  mpz_powm(ctx->pt, ctx->ct, ctx->d, ctx->n);
  char* hexString = NULL;
  if((hexString = mpz_get_str(NULL, 16, ctx->pt)) == NULL){
    printf("Error converting mpz_t to string. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  return hexString;
}

//Encrypts a string of ASCII values into a decimal number string to return
char* encrypt(rsaCtx *ctx, char* hexString){
  if(mpz_set_str(ctx->pt, hexString, 16)){
    printf("Error converting string to mpz_t. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  mpz_powm(ctx->ct, ctx->pt, ctx->e, ctx->n);
  char* encrypted = NULL;
  if((encrypted = mpz_get_str(NULL, 16, ctx->ct)) == NULL){
    printf("Error converting mpz_t to string. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  return encrypted;
}

//Generates a 2048 bit prime number with /dev/random
void generatePrime(mpz_t prime){
  gmp_randstate_t state;
  unsigned long int seed;
  gmp_randinit_default(state);
  FILE* fp = NULL;
  if((fp = fopen("/dev/random","rb")) == NULL){
    printf("Error opening /dev/random. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  if(fread(&seed, sizeof(unsigned long int), 1, fp) != 1){
    printf("Error reading from /dev/random. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  if(fclose(fp) != 0){
    printf("Error closing file. Exiting...\n");
    exit(EXIT_FAILURE);
  } 
  gmp_randseed_ui(state, seed);
  mpz_urandomb(prime, state, 2048);
  while(mpz_probab_prime_p(prime, 50) == 0){
    mpz_urandomb(prime, state, 2048);
  }
  gmp_randclear(state);
}

//Get user input and remove newline character
char* getInput(){
  printf("\nNow time to encrypt. Please enter text you wish to encrypt: ");
  char* input = (char*) malloc(129 * sizeof(char));
  if(input == NULL){
    printf("Error allocating memory. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  if(fgets(input, 128, stdin) == NULL || input[0] == '\n'){
    printf("Error getting input. Exiting...\n");
    exit(EXIT_FAILURE);
  }
  input[strlen(input)-1] = '\0';
  return input;
}

//Calculates phi(n) with (p-1)*(q-1)
void phiOfN(mpz_t p, mpz_t q, mpz_t phiN){
  mpz_t pSub1, qSub1;
  mpz_inits(pSub1, qSub1, NULL);
  mpz_sub_ui(pSub1, p, 1);
  mpz_sub_ui(qSub1, q, 1);
  mpz_mul(phiN, pSub1, qSub1);
  mpz_clears(pSub1, qSub1, NULL);
}

void printKeys(rsaCtx* ctx){
  gmp_printf("Public Key:\n n: %Zd\ne: %Zd\n", ctx->n, ctx->e);
  gmp_printf("Private Key:\n n: %Zd\nd: %Zd\n", ctx->n, ctx->d);
}

//Initalize mpz_t variables and generate relevant RSA values
void initCtx(rsaCtx *ctx){
  mpz_inits(ctx->p,
            ctx->q,
            ctx->n,
            ctx->phiN,
            ctx->e,
            ctx->d,
            ctx->pt,
            ctx->ct,
            NULL);
  mpz_set_ui(ctx->e, 65537);
  generatePrime(ctx->p);
  generatePrime(ctx->q);
  mpz_mul(ctx->n, ctx->p, ctx->q);
  phiOfN(ctx->p, ctx->q, ctx->phiN);
  mpz_invert(ctx->d, ctx->e, ctx->phiN);
}

/**
 * rsacrypt.c
 *  RSA Encrypt/Decrypt & Sign/Verify Test Program for OpenSSL
 *  wrtten by blanclux
 *  This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* socket */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> /* close */
#include <netdb.h> /* gethostbyname */
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef struct in_addr IN_ADDR;
#define BUF_SIZE 1024
#define PORT	 8852

#define KEYBIT_LEN	2048

static void
printHex(const char *title, const unsigned char *s, int len)
{
	int     n;
	printf("%s:", title);
	for (n = 0; n < len; ++n) {
		if ((n % 16) == 0) {
			printf("\n%04x", n);
		}
		printf(" %02x", s[n]);
	}
	printf("\n");
}

RSA*
createRSAWithFilename(char *filename, int public)
{
    FILE * fp = fopen(filename,"rb");

    if(fp == NULL) {
        printf("Unable to open file %s \n",filename);
        return NULL;
    }
    RSA *rsa= RSA_new() ;

    if(public) {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }

    return rsa;
}


int
doCrypt(RSA *pubkey, unsigned char *data, int dataLen, unsigned char encrypt[])
{
	int encryptLen, decryptLen;

	encryptLen = RSA_public_encrypt(dataLen, data, encrypt, pubkey,
									RSA_PKCS1_OAEP_PADDING);

	return encryptLen;
}


int
doDecrypt(RSA *prikey, unsigned char encrypt[], int encryptLen, unsigned char decrypt[])
{
	int decryptLen;

	decryptLen = RSA_private_decrypt(encryptLen, encrypt, decrypt, prikey,
									 RSA_PKCS1_OAEP_PADDING);

	return decryptLen;
}

int
doSign(RSA *prikey, unsigned char *data, int dataLen, unsigned char sign[], unsigned int *signLen)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int ret;

	SHA256(data, dataLen, hash);
    printHex("SHA", hash, SHA256_DIGEST_LENGTH);

	/* Sign */
	ret = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
				   signLen, prikey);

    return ret;
}

int
doVerify(RSA *pubkey, unsigned char *data, int dataLen, unsigned char sign[], unsigned int signLen)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int ret;

    SHA256(data, dataLen, hash);

	ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
					 signLen, pubkey);

    return ret;
}

int
main(int argc, char *argv[])
{

    RSA* priv = NULL;
    RSA* pub = NULL;
	unsigned char sign[KEYBIT_LEN/8];
    unsigned int signLen;
	unsigned char encrypt[KEYBIT_LEN/8], decrypt[KEYBIT_LEN/8];

    char* text = "Hello";
    unsigned char* data = (unsigned char *) text;
    int dataLen = strlen(text);

    printf("< Create priv key >\n");
    priv = createRSAWithFilename("/media/aussedat/MyFiles/Documents/scripts/python/pyticator/id_rsa", 0);
    printf("< Create pub key >\n");
    pub = createRSAWithFilename("/media/aussedat/MyFiles/Documents/scripts/python/pyticator/id_rsa.pub", 1);

    printHex("TEXT", data, dataLen);

    printf("< Public encryption >\n");
    int encryptLen = doCrypt(pub, data, dataLen, encrypt);
    printHex("ENCRYPT", encrypt, encryptLen);
	printf("Encrypt length = %d\n", encryptLen);

    printf("< Private decryption >\n");
    int decryptLen = doDecrypt(priv, encrypt, encryptLen, decrypt);
    printHex("DECRYPT", decrypt, decryptLen);
	printf("Decrypt length = %d\n", decryptLen);

    printf("< Sign data >\n");
    int ret = doSign(priv, data, dataLen, sign, &signLen);
	printHex("SIGN", sign, signLen);
	printf("Signature length = %d\n", signLen);
	printf("RSA_sign: %s\n", (ret == 1) ? "OK" : "NG");

    FILE* out = fopen("encryption.bin", "w");
    fwrite(sign, sizeof(*sign), signLen, out);
    fclose(out);

    text = "Hello";
    data = (unsigned char *) text;
    dataLen = strlen(text);

    printf("< Verify Sign data >\n");
    ret = doVerify(pub, data, dataLen, sign, signLen);
    printf("RSA_Verify: %s\n", (ret == 1) ? "true" : "false");

    printf("< End >\n");

    RSA_free(pub);
    RSA_free(priv);


    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    SOCKADDR_IN sin = { 0 };
    struct hostent *hostinfo;

    if(sock == INVALID_SOCKET)
    {
        perror("socket()");
        exit(errno);
    }

    hostinfo = gethostbyname("localhost");
    if (hostinfo == NULL)
    {
        fprintf (stderr, "Unknown host %s.\n", "localhost");
        exit(EXIT_FAILURE);
    }

    sin.sin_addr = *(IN_ADDR *) hostinfo->h_addr_list[0];
    sin.sin_port = htons(PORT);
    sin.sin_family = AF_INET;

    if(connect(sock,(SOCKADDR *) &sin, sizeof(SOCKADDR)) == SOCKET_ERROR)
    {
        perror("connect()");
        exit(errno);
    }

    if(send(sock, sign, signLen, 0) < 0)
    {
        perror("send()");
        exit(errno);
    }

	return 0;
}

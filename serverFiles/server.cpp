#include <iostream>
#include <string>
#include <openssl/ssl.h> 
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/dh.h>

using namespace std;

#define BUFSIZE 1024

  /////////////////////////////////////
 // Auxilliarry Functions
//////////////////////
/* Function: error digest, used to print info on current error
 *  --given in lab8--
 */
void printErrors() {
    char buff[BUFSIZE];
    int error;
    while ((error = ERR_get_error()) != 0) {
        ERR_error_string_n(error, buff, sizeof(buff));
        printf("*** %s\n", buff);
    }
}

/* Function: used for converting char array as byte representation
 * 		to hexadecimal output to a string
 *  -- given in lab8-- modified to output string instead of straight to console
 */
string byteToHex(const unsigned char* buff, const int len) {
    string s = "";
    for(int i = 0; i < len; i++) {
        char temp[EVP_MAX_MD_SIZE];
        sprintf(temp, "%02x", buff[i] & 0xFF);
        s += temp;
    }
    return s;
}

/* Function: message display aid
 *	char from[] = char array to be translated to string
 * 	int size = size of incoming buffer
 */
string cToS(char from[], int size) {
  	char to[size];
  	for(int i = 0 ; i < size; i++)
  		to[i] = from[i];
  	return to;
}

/* Function: message display aid (mimic of cToS)
 *	unsigned char from[] = char array to be translated to string
 * 	int size = size of incoming buffer
 */
string unsignCToS(unsigned char from[], int size) {
  	char to[size];
  	for(int i = 0 ; i < size; i++)
  		to[i] = (char)from[i];
  	return to;
}

  /////////////////////////////////////
 // SERVER START
//////////////////////
int main(int argc, char** argv) {
  	// Initialize Server
  	ERR_load_crypto_strings();
  	SSL_load_error_strings();
  	SSL_library_init();
  	setbuf(stdout, NULL);
  
  	// Get arguments
  	// Useage: server -port portnumber
  	if (argc < 2) {
      printf("Useage: server -port portnumber\n");
      exit(EXIT_FAILURE);
    }
  char* port = argv[2];
  
 	cout << "<<<<<  SERVER  >>>>>" << endl;
  	 ///////////////////////////////////////////////////////////////////////
  	// 1. Wait for client connection request, and establish an SSL connection with the client
  	cout << "(1) Waiting for Client SSL Connection...";
  
  	// Set DH object
  	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
  	int dhError;
  	DH_check(dh, &dhError);
  	if (dhError != 0) {
      	cout << "[ERROR] Diffie-Helman generate_parameters...EXITING" << endl;
      	printErrors();
      	exit(EXIT_FAILURE);
    }
  
  	// Set context
  	SSL_CTX* serverCTX = SSL_CTX_new(SSLv23_method());
  	SSL_CTX_set_verify(serverCTX, SSL_VERIFY_NONE, NULL);
  	SSL_CTX_set_tmp_dh(serverCTX, dh);
  	if (SSL_CTX_set_cipher_list(serverCTX, "ALL") != 1) {
      	cout << "[ERROR] could not set cipher list...EXITING" << endl;
      	printErrors();
      	exit(EXIT_FAILURE);
    }
  
  	// Set BIO
  	BIO* server = BIO_new(BIO_s_accept());
  	BIO_set_accept_port(server, port);
  	BIO_do_accept(server);
  
  	// Set SSL
  	SSL* serverSSL = SSL_new(serverCTX);
  	if (!serverSSL) {
      	cout << "[ERROR] could not create new SSL object...EXITING" << endl;
      	printErrors();
      	exit(EXIT_FAILURE);
    }
    // Set SSL_accept
  	SSL_set_accept_state(serverSSL);
  	SSL_set_bio(serverSSL, server, server);
  	if (SSL_accept(serverSSL) <= 0) {
      	cout << "[ERROR] SSL_accept failure...EXITING" << cout;
      	printErrors();
      	exit(EXIT_FAILURE);
    }
  
  	cout << "CONNECTED" << endl
  		<< "Listening On Port ::: " << port << endl;
  
  	 ///////////////////////////////////////////////////////////////////////
  	// 2. Receive an encrypted challenge from the client and decrypt it using the RSA private key
  	cout << "(2) Waiting for Client Challenge...";
	// constructing the void *buf paramater for SSL_read
  	char chalBuf[BUFSIZE];
  	memset(chalBuf, 0 , sizeof(chalBuf));
  	// SSL_read(SSL *ssl, void *buf, int num)
  	int buff_len  = SSL_read( serverSSL, chalBuf, BUFSIZE );
  	cout << "(2) COMPLETE" << endl;
  	
  	cout << "(2) RSA Decrypting Challenge...";
  	// convert chalBuf[] to unsigned char[]
  	unsigned char uchalBuf[BUFSIZE];
  	for(int i = 0; i < BUFSIZE; i++) {
		uchalBuf[i] = (unsigned char)chalBuf[i];
  	}
  
  	unsigned char DECrandBuf[BUFSIZE];
  	BIO *privateKey = BIO_new_file("rsaprivatekey.pem", "r");
  	RSA *rsaPriv = PEM_read_bio_RSAPrivateKey(privateKey, NULL, 0, NULL);
  	// int RSA_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
  	RSA_private_decrypt(BUFSIZE, uchalBuf, DECrandBuf, rsaPriv, RSA_PKCS1_PADDING);
  	cout << "COMPLETE" << endl;
  	
//  string challenge = unsignCToS(DECrandBuf, BUFSIZE);
  	string challenge = byteToHex((const unsigned char* )chalBuf, sizeof(DECrandBuf)).c_str();
  	
  	cout << "(2) Recieved Challenge ::: " << challenge << endl;
  	BIO_free_all(privateKey);
  	
 	 ///////////////////////////////////////////////////////////////////////
  	// 3. Hash the challenge using SHA1
  	cout << "(3) Hashing Challenge (SHA1)..." << endl;
  	// Compute the SHA1 hash
  	// Using a BIO_s_mem to chain the hash to
  	// BIO_new(BIO_METHOD *type);
  	BIO* memIO = BIO_new(BIO_s_mem());
  
  	//BIO_write(BIO *b, const void *buf, int len);
  	BIO_write(memIO, DECrandBuf, buff_len);
  

  	BIO *hash = BIO_new(BIO_f_md());
  	BIO_set_md(hash ,EVP_sha1());
  	BIO_push(hash, memIO);
  

  	char tohashedRAND[EVP_MAX_MD_SIZE];
  	int hashLen = BIO_gets(hash, tohashedRAND, EVP_MAX_MD_SIZE);
  	string hashedRAND = byteToHex((const unsigned char*)tohashedRAND, hashLen);
  
  	cout << "(3) Hashed Challenge ::: " << hashedRAND << endl;

  	BIO_free_all(hash);
  
  	 ///////////////////////////////////////////////////////////////////////
  	// 4. Sign the hash
  	cout << "(4) Signing Hash...";
  
  	unsigned char readBuf[128];
  
	// A bug is causing me to recreate the rsa object
  	privateKey = BIO_new_file("rsaprivatekey.pem","r");
  	RSA *rsaPriv2 = PEM_read_bio_RSAPrivateKey(privateKey, NULL, 0, NULL);
  	int siglen = RSA_private_encrypt(RSA_size(rsaPriv2)-11, (const unsigned char*)tohashedRAND, readBuf, rsaPriv2, RSA_PKCS1_PADDING);
  	cout << "COMPLETE" << endl;
  	
  	char* signature=(char*)readBuf;
  	string hashSig = byteToHex((const unsigned char*)signature, siglen);
  	cout << "(4) Signed Hash ::: " << hashSig << endl;
  
  	 ///////////////////////////////////////////////////////////////////////
  	// 5. Send the signed hash to the client
  	cout << "(5) Sending Signed Hash to Client...";
 	SSL_write(serverSSL, signature, BUFSIZE);
  	cout << "COMPLETE" << endl;
  
  	 ///////////////////////////////////////////////////////////////////////
  	// 6. Receive a filename request from the client
  	cout << "(6) Receiving Request from Client...";

  	char filename[BUFSIZE];
  	SSL_read(serverSSL, filename, BUFSIZE);
  	
  	cout << "COMPLETE" << endl
  		<< "(6) File Request ::: " <<  filename << endl;
  
  	 ///////////////////////////////////////////////////////////////////////
  	// 7. Send the (entire) requested file back to the client
  	cout << "(7) Sending Requested File...";
  	
  	//Set the outgoing file
  	char sendBuf[BUFSIZE];
  	int amountRead = 0, amountSent = 0, writen;
  	BIO *outfile = BIO_new_file(filename, "r");
  	if(outfile == NULL) {
      	cout << "[ERROR] File could not be read" << endl;
      	return 0;
  	} 
  	else {
      	while ((amountRead =  BIO_read(outfile, sendBuf, BUFSIZE)) >= 1)
        {
          	writen = SSL_write(serverSSL, sendBuf, amountRead);
          	amountSent += writen;
        }
    } 
  	cout << "COMPLETE" << endl;

  	 ///////////////////////////////////////////////////////////////////////
  	// 8. Close the connection
  	cout << "(8) Closing connection...";
  
  	SSL_shutdown(serverSSL);
  	BIO_reset(server);
  	cout << "COMPLETE" << endl;
  	BIO_free_all(server);
  	cout << "<<<<<  EXITING SERVER  >>>>>" << endl;
  	return EXIT_SUCCESS;
}

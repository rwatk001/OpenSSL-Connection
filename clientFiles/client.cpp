#include <iostream>
#include <string>
#include <openssl/ssl.h> 
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

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

  /////////////////////////////////////
 // CLIENT START
//////////////////////
int main(int argc, char** argv) {
  	// Initialize Client
  	SSL_library_init();
  	ERR_load_crypto_strings();
  	SSL_load_error_strings();
  	setbuf(stdout, NULL);
  
  	// Get arguments
  	// Useage: client -server serveraddress -port portnumber filename
  	if (argc < 6) {
      	cout << "Useage: client -server serveraddress -port portnumber filename" << endl;
      	exit(EXIT_FAILURE);
    }
  	char* server = argv[2];
  	char* port = argv[4];
  	char* filename = argv[5];
  	bool state = true;
  
  	// Formatting the aurgument input
  	string sServer = server;
  	string sPort = port;
  	string servConnect = sServer + ":" + sPort;
  	char serverBuf[256];
  	strcpy(serverBuf, servConnect.c_str());
  
  	cout << "<<<<<  CLIENT  >>>>>" << endl;
  	 ///////////////////////////////////////////////////////////////////////
  	// 1. Establish SSL connection to the server
  	cout << "(1) Establishing SSL connection with the server..." << endl;
  
  	// Set context
  	SSL_CTX* clientCTX = SSL_CTX_new(SSLv23_method());
  	SSL_CTX_set_verify(clientCTX, SSL_VERIFY_NONE, NULL);
  	if (SSL_CTX_set_cipher_list(clientCTX, "ADH") != 1) {
      	cout << "[ERROR] could not set cipher list...EXITING" << endl;
      	printErrors();
      	exit(EXIT_FAILURE);
    }
  
  	// Set BIO
  	BIO* client = BIO_new_connect(serverBuf);
 	if (BIO_do_connect(client) != 1) {
      	cout << "[ERROR] bad server address...EXITING" << endl;
      	printErrors();
      	exit(EXIT_FAILURE);
    }
  
  	// Set SSL
  	SSL* clientSSL = SSL_new(clientCTX);
  	if (!clientSSL) {
      	cout << "[ERROR] could not create new SSL object...EXITING" << endl;
      	exit(EXIT_FAILURE);
    }
  	SSL_set_bio(clientSSL, client, client);
  	if (SSL_connect(clientSSL) <= 0) {
      	cout << "[ERROR] SSL_connect failure...EXITING" << cout;
      	printErrors();
      	exit(EXIT_FAILURE);
    }
  
  	cout << "(1) SUCCESSFUL - Connected to: " << servConnect << endl;
  
  	 ///////////////////////////////////////////////////////////////////////
  	// 2. Seed a cryptographically secure PRNG and use it to generate a random number (challenge)
  	cout << "(2) Generating Challenge...";
  
  	//RAND_bytes(unsigned char *buf, int num);
  	unsigned char randBuf[BUFSIZE];
  	int checkrand = RAND_bytes(randBuf,BUFSIZE);
  	if( checkrand != 1)
	printErrors();
   	cout << " COMPLETE" << endl;
   	
   	 ///////////////////////////////////////////////////////////////////////
  	// 3. Encrypt the challenge using the server’s RSA public key, and send the encrypted challenge to the server
   	cout << "(3) RSA Encrypting Challenge...";
   	unsigned char ENCrandBuf[BUFSIZE];
   	BIO *publicKey = BIO_new_file("rsapublickey.pem", "r");
   	RSA *rsaPub  = PEM_read_bio_RSA_PUBKEY(publicKey, NULL, 0, NULL);
   	// int RSA_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
   	RSA_public_encrypt(BUFSIZE, randBuf, ENCrandBuf, rsaPub, RSA_PKCS1_PADDING);
	cout << " COMPLETE" << endl;

	cout << "(3) Sending Challenge to Server..." << endl;
  	//SSL_write(SSL *ssl, const void *buf, int num);
  	char toServ[BUFSIZE];
  	// Using memset for const void *buf parameter 
  	memset(toServ, 0 , sizeof(toServ));
  	memcpy(toServ, ENCrandBuf, sizeof(toServ));
  
  
  	int buff_len = SSL_write(clientSSL, toServ, BUFSIZE);
  
  	cout << "(3) SUCCESSFUL - Challenge Sent" << endl;
  	cout << "(3) CHALLENGE ::: " << byteToHex((const unsigned char*) ENCrandBuf, BUFSIZE).c_str() << endl;
  
  	 ///////////////////////////////////////////////////////////////////////
  	// 4. Hash the un-encrypted challenge using SHA1 	
	cout << "(4) Hashing Challenge (SHA1)..." << endl;
	// Compute the SHA1 hash
  	// Using a BIO_s_mem to chain the hash to
  	// BIO_new(BIO_METHOD *type);
  	BIO* memIO = BIO_new(BIO_s_mem());
  
  	//BIO_write(BIO *b, const void *buf, int len);
  	BIO_write(memIO, randBuf, sizeof(randBuf));
  
  	BIO *hash = BIO_new(BIO_f_md());
  	BIO_set_md(hash ,EVP_sha1());
  	BIO_push(hash ,memIO);
  
  	char tohashedRAND[EVP_MAX_MD_SIZE];
  	int hashLen = BIO_gets(hash, tohashedRAND, EVP_MAX_MD_SIZE);
  	string hashedRAND = byteToHex((const unsigned char*)tohashedRAND, hashLen);
  
  	cout << "(4) Hashed Challenge ::: " << hashedRAND << endl;

  	BIO_free_all(hash);
	
  	 ///////////////////////////////////////////////////////////////////////
  	// 5. Receive the signed hash of the random challenge from the server, and recover the hash using the RSA public key
  	cout << "(5) Receiving Signed Hash from Server..." << endl;
 
  	char serverHash[BUFSIZE];
  	memset(serverHash, 0, sizeof(serverHash));
  
  	// SSL_read(SSL *ssl, void *buf, int num)
  	int  recSigHashLen = SSL_read(clientSSL, serverHash, 128);
  	
  	string recSigHash = byteToHex((const unsigned char*)serverHash, hashLen);
  
  	cout << "(5) Server - Signed Hash ::: " << recSigHash << endl;
  	
  	 ///////////////////////////////////////////////////////////////////////
  	// 6. Compare the generated and recovered hashes above, to verify that the server received and decrypted the challenge properly
  	cout << "(6) Authenticating...";
  	unsigned char DECserverHash[BUFSIZE];
  
	// Using the RSA Public Key from section (3)
  	RSA_public_decrypt(RSA_size(rsaPub), (const unsigned char*)serverHash, DECserverHash, rsaPub, RSA_PKCS1_PADDING);
  
  	string serverSigned = byteToHex((const unsigned char*)serverHash, 20);
  	string decrypted = byteToHex((const unsigned char*)DECserverHash, 20); 
  
	if (decrypted != hashedRAND) {
		cout << endl << "[ERROR] Authentification Failure...EXITING" << endl;
      	exit(EXIT_FAILURE);  
  	}
  
  	cout << "AUTHENTICATED" << endl
  		<< "(6) Server - Decrypted Hash ::: " << decrypted << endl;

  	BIO_free(publicKey);
  
  	 ///////////////////////////////////////////////////////////////////////
	// 7. Send the server a filename (file request)
  	cout << "(7) Sending File Request...";

	BIO *sendBuf = BIO_new(BIO_s_mem());
	// Construct filename
//	string prefix = "../serverFiles/";
  	string request = filename;
  	request+='\0';

  	//BIO_puts(BIO *b,const char *buf);
  	int putsFile = BIO_puts(sendBuf, request.c_str());

  	//SSL_write(SSL *ssl, const void *buf, int num);
  	SSL_write(clientSSL, request.c_str(), request.size());
  
  	cout << "COMPLETE" << endl
  		<< "(7) Requesting ::: " << filename << endl;
  
  	 ///////////////////////////////////////////////////////////////////////
	// 8. Receive and display the contents of the file requested
 	cout << "(8) Receiving Request Response..." << endl
 		<< "::: File Contents Stream :::" << endl;
  
  	// Construct new BIO for the read of the requested file
  	string recieved = filename;
  	recieved = "REQ_" + recieved;
  	BIO* requestFile = BIO_new_file(recieved.c_str(), "w");
  	char fromFile[BUFSIZE]; 
  
  	// Using loop from simple.cpp in lab8
  	string written;
  	int amountRead = 0;
  	// Somehow there is padding left in my buffer but I correct it with a forced
  	// ignore of the first input string 
  	int dump = 0;
  	while ((amountRead = SSL_read(clientSSL, fromFile, BUFSIZE)) >= 1) {
  		if (dump > 0) {
     		BIO_write(requestFile, fromFile, amountRead);
    		written = cToS(fromFile, amountRead);
      		cout << written;
      	}
      	dump++;
    }
  
  	BIO_free(requestFile);
  	cout << "(8) File Transfer COMPLETE" << endl;  
  	
  	 ///////////////////////////////////////////////////////////////////////
	// 9. Close the connection
  	cout << "(9)  Closing the connection...";
  	SSL_shutdown(clientSSL);
	cout << "COMPLETE" << endl;
  	printErrors();
  	SSL_CTX_free(clientCTX);
  	SSL_free(clientSSL);
  	cout << "<<<<<  EXITING CLIENT  >>>>>" << endl;
  	return EXIT_SUCCESS;
}
  /////////////////////////////////////
 // CLIENT END
//////////////////////

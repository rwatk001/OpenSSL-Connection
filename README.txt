The project utilizes OpenSSL to establish an authenticated connection between a sever and client.



-------------------
--- SERVER
------------------
	The files for the SERVER side are in the sub-directory 'serverFilesls '.
		They include:
			MAKEFILE
			rsaprivatekey.pem
			server.cpp
			watkins.txt
			
	watkins.txt contains the text of an article headed with Ryan Watkins.
			
	To run:
		type 'make' to create executable 'server'
		type 'server -port portnumber' to run
		
		The server will then pause and wait for the client to connect.
		
	Output:
		The various steps of the varification and file transfer process will output to the console.
		
		
-------------------
--- CLIENT
------------------
	The files for the CLIENT side are in the sub-directory 'clientFiles'
		They include
			MAKEFILE
			rsapublickey.pem
			client.cpp
			
	To run:
		type 'make' to create executable 'client'
		type 'client -server serveraddress -port portnumber filename' to run
		
		Be sure the server side is running or client will not run
		
	Output:
		The various steps of the varification and file transfer process will output to the console as will the full file text when the tansfer is complete.
		The file transfered will have the prefix REQ (requested) to distinguish it from the original.

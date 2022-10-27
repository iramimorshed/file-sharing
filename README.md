# Encrypted File-Sharing System

## Description 
This project is an encrypted file-sharing system similar to Dropbox. I implemented eight different functions allowing users to: 
1. Authenticate themselves with a username and password 
2. Save and encrypt files to Datastore adversary 
3. Load and decrypt files from Datastore adversary 
4. Overwrite saved encrypted files 
5. Append to saved encrypted files 
6. Share files with other users 
7. Revoke access to files from other users 

## Encryption Schemes 
Because of the Datastore adversary, which can tamper with and overwrite files, files must be encrypted to guarantee confidentiality and integrity when storing in Datastore. I used a combination of encryption schemes such as symmetric encryption (where keys are generated and shared among users), asymetric encryption (ses a pair of public key and a private key to encrypt and decrypt messages when communicating), and hybrid encryption (which combines the previous two schemes).

## Link to Write-Up 
For some details regarding the objects invovled and functions involved when creating the eight functions, please refer to: https://tinyurl.com/encrypt-files




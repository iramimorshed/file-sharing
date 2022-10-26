package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	sourceKey, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", sourceKey.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

/*
	Definition of User struct:
	1. Username - unencrypted string
	2. PKEDecKEy, DSSignKey - private RSA Decryption Key and private RSA Sign Key
	3. Datastore_key, HMAC_key, SymEnc_key - keys for User encryption
	4. Files - each file has its own storage_key that maps to its own file_data, another struct
	5. Lockboxes - each file has its own storage_key that maps to an array of lockbox_data
*/
type User struct {
	Username                            string
	PKEDecKey, DSSignKey                userlib.PrivateKeyType
	Datastore_key, HMAC_key, SymEnc_key []byte
	Files                               map[userlib.UUID]File_Data
	Lockboxes                           map[userlib.UUID][]Lockbox_Data
}

/*
	Definition of File struct:
	1. Content_length - number of appends that have been made to file, or nodes
	2. Owner - who initially stored the file
	3. Start - pointer to first node in Datastore
	4. End - pointer to last node in Datastore
*/
type File struct {
	Content_length    int
	Owner, Start, End userlib.UUID
}

/*
	Definition of File_Data struct:
	1. Datastore_key - pointer to encrypted File in Datastore
	2. File_symenc_key, File_hmac_key - symmetric keys to encrypt/decrypt File objects
	3. Node_symenc_key, Node_hmac_key - symmetric keys to encrypt/decrypt Node objects
*/
type File_Data struct {
	Datastore_key   userlib.UUID
	File_symenc_key []byte
	File_hmac_key   []byte
	Node_symenc_key []byte
	Node_hmac_key   []byte
}

/*
	Definition of Node_Content struct:
	1. Content - file content
	2. Next - pointer to next node
*/
type Node_Content struct {
	Content []byte
	Next    userlib.UUID
}

/*
	Definition of Lockbox struct:
	1. File_encrypt_key - appended symmetric keys to encrypt/decrypt File objects
	2. Node_encrypt_key - appended symmetric keys to encrypt/decrypt Node objects
	3. File_location - pointer to encrypted File in Datastore
*/
type Lockbox struct {
	File_encrypt_key []byte
	Node_encrypt_key []byte
	File_location    userlib.UUID
}

/*
	Definition of Lockbox_Data struct:
	1. Location - pointer to location of encrypted Lockbox in Datastore
	2. Encrypt_keys - symmetric keys to encrypt/decrypt Lockbox in Datastore
	3. Shared_user - who was sent or who sent the invite
*/
type Lockbox_Data struct {
	Location     userlib.UUID
	Encrypt_keys []byte
	Shared_user  string
}

/*
	Definition of Invitation struct
	1. Lockbox_key - pointer to encrypted Lockbox in Datastore
	2. Asymmenc_keys - symmetrically derived keys encrypted under assymetric encryption scheme
*/
type Invitation struct {
	Lockbox_key   userlib.UUID
	Asymmenc_keys []byte
}

/*
	Helper function to derive new keys from a source key and a keyword
	Also stores new key in Keystore along with associated public key
*/
func DeriveFromSourceKey(source_key userlib.UUID, key_word string, value userlib.PublicKeyType) (err error) {
	// Marshal source_key into bytes
	source_key_bytes, err := json.Marshal(source_key)
	if err != nil {
		return errors.New("cannot Marshal sourceKey into bytes array representation")
	}

	// Derive new key using key_word argument and HashKDF function
	new_key, err := userlib.HashKDF(source_key_bytes[:16], []byte(key_word))
	if err != nil {
		return errors.New("cannot generate key from source key with HashKDF")
	}

	// Store (new_key, public key) in Datastore
	err = userlib.KeystoreSet(string(new_key), value)
	if err != nil {
		return errors.New("unable to store a public PKEEncKey/DSVerifyKey in Keystore")
	}

	return nil
}

/*
	Initialize a User
*/
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Instantiate a User struct
	var userdata User

	// Return error if empty username is provided
	if len(username) == 0 {
		return nil, errors.New("username is empty")
	}

	// Determine if username is unique or if it already exists in Keystore
	source_key, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}

	_, exists := userlib.KeystoreGet(source_key.String())
	if exists {
		return nil, errors.New("username already exists")
	}

	// Generate RSA public/private keys and RSA Digital Signature sign/verify keys
	pk_public_key, pk_private_key, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("cannot generate a pair of RSA public/private keys")
	}

	ds_sign_key, ds_verify_key, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("cannot generate a pair of Digital Signature keys")
	}

	// Store public verify key in Keystore using HashKDF function and source_key
	err = DeriveFromSourceKey(source_key, "verify", ds_verify_key)
	if err != nil {
		return nil, errors.New("unable to derive new key from source key")
	}

	// Store RSA public key in Keystore
	err = userlib.KeystoreSet(source_key.String(), pk_public_key)
	if err != nil {
		return nil, errors.New("unable to store a public PKEKey in Keystore")
	}

	// Assign userdata's fields and store private keys
	userdata.Username = username
	userdata.Files = make(map[uuid.UUID]File_Data)
	userdata.Lockboxes = make(map[uuid.UUID][]Lockbox_Data)
	userdata.PKEDecKey = pk_private_key
	userdata.DSSignKey = ds_sign_key

	// Derive keys for symmetric encryption, HMAC, and storing in Datastore
	userdata.Datastore_key = userlib.Argon2Key([]byte(password), []byte(username), uint32(16))
	userdata.HMAC_key = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.HashSizeBytes))
	userdata.SymEnc_key = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESBlockSizeBytes))

	// Encrypt userdata and store in Datastore
	user_bytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("cannot Marshal User struct into a JSON byte array representation")
	}

	// Derive IV for symmetric encryption, then a check-sum, and append to encrypted userdata
	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	userEncrypted := userlib.SymEnc(userdata.SymEnc_key[:16], IV, user_bytes)
	check_sum, err := userlib.HMACEval(userdata.HMAC_key[:16], userEncrypted)
	if err != nil {
		return nil, errors.New("unable to generate a checksum through HMACEval")
	}

	userEncryptedHMAC := append(userEncrypted, check_sum...)

	// Convert byte Datastore key to UUID and store encrypted userdata in Datastore
	ds_key_uuid, err := uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return nil, errors.New("cannot convert Datastore_key byte array into a UUID")
	}

	// userlib.DebugMsg("user: %v", user_bytes)
	// Store encrypted user in Datastore
	userlib.DatastoreSet(ds_key_uuid, userEncryptedHMAC)

	// Return pointer to userdata and nil error
	return &userdata, nil
}

/*
	Obtains the User struct of a user who has already been initialized and returns a pointer to it
*/
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// Verify existence of user
	hash := userlib.Hash([]byte(username))
	source_key, err := uuid.FromBytes(hash[:16])
	if err != nil {
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}

	_, exists := userlib.KeystoreGet(source_key.String())
	if !exists {
		return nil, errors.New("User does not exist")
	}

	// Verify password by first deriving Datastore key and converting into UUID from bytes
	ds_key := userlib.Argon2Key([]byte(password), []byte(username), uint32(16))
	ds_key_uuid, err := uuid.FromBytes(ds_key)
	if err != nil {
		return nil, errors.New("cannot convert Datastore_key byte array into a UUID")
	}

	// Derive HMAC and symmetric encryption keys using deterministic Argon2Key
	HMAC_key := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.HashSizeBytes))
	SymEnc_key := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESBlockSizeBytes))

	// Finally, verify password using derived Datastore key
	user_encrypt_hmac, valid := userlib.DatastoreGet(ds_key_uuid)
	if !valid {
		return nil, errors.New("incorrect password")
	}

	// Separate encrypted data, verify integrity, and decrypt
	length := len(user_encrypt_hmac) - 64
	ciphertext := user_encrypt_hmac[:length]
	check_sum := user_encrypt_hmac[length:]

	// Compare check_sum from encrypted data and derived check_sum
	sum, err := userlib.HMACEval(HMAC_key[:16], ciphertext)
	if err != nil {
		return nil, errors.New("unable to generate a checksum through HMACEval")
	}

	equal := userlib.HMACEqual(check_sum, sum)
	if !equal {
		return nil, errors.New("integrity is compromised...data is corrupted")
	}

	// Decrypt ciphertext using previously generated key for symmetric encryption
	plaintext := userlib.SymDec(SymEnc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return nil, errors.New("corrupted JSON Unmarshal")
	}

	// Return pointer to user and nil error
	userdataptr = &userdata
	return userdataptr, nil
}

/*
	Given a filename in the personal namespace of the caller, this function
	persistently stores the given content for future retrieval using the same filename
*/
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Pull most recent version of userdata from Datastore
	ds_key_uuid, err := uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return errors.New("unable to convert userdata's datastore key to a uuid")
	}

	// Decrypt and verify integrity of most recent version of userdata
	loaded_user_bytes, exists := userlib.DatastoreGet(ds_key_uuid)
	if !exists {
		return errors.New("userdata does not exist in Datastore")
	}

	length := len(loaded_user_bytes) - 64
	ciphertext := loaded_user_bytes[:length]
	check_sum := loaded_user_bytes[length:]
	sum, err := userlib.HMACEval(userdata.HMAC_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum for userdata through HMACEval")
	}

	equal := userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("userdata integrity is compromised...data is corrupted")
	}

	plaintext := userlib.SymDec(userdata.SymEnc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return errors.New("corrupted JSON Unmarshal")
	}

	// Declare file_data and file
	var file_data File_Data
	var file File

	// This will be the primary key used in the Files and Lockboxes maps in userdata
	storage_key, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("unable to create storage key for new file")
	}

	// Check if this file of this name exists in the namespace
	file_data, exists = userdata.Files[storage_key]
	var owner userlib.UUID

	// If this file exists in userdata's namespace:
	if exists {
		var file File
		_, file_exists := userlib.DatastoreGet(file_data.Datastore_key)

		// If userdata has lockboxes then proceed
		if len(userdata.Lockboxes[storage_key]) > 0 {
			encrypted_box_bytes, box_exists := userlib.DatastoreGet(userdata.Lockboxes[storage_key][0].Location)

			// If both the file and box have been deleted this means a revoked user is trying to gain access
			if !file_exists && !box_exists {
				return errors.New("revoked users cannot access deleted lockbox or file")
			}

			// If the file does not exist but the box does, this means we need to update the user's lockbox
			if !file_exists && box_exists && len(userdata.Lockboxes[storage_key]) > 0 {
				// Retrieve most recent version of lockbox (updated through RevokeAcess) and update userdata.Files
				var box Lockbox

				// Retrieve symmetrically derived keys
				symenc_key := userdata.Lockboxes[storage_key][0].Encrypt_keys[:userlib.AESBlockSizeBytes]
				hmac_key := userdata.Lockboxes[storage_key][0].Encrypt_keys[userlib.AESBlockSizeBytes:]

				// Decrypt and verify integrity of encrypted lockbox
				length = len(encrypted_box_bytes) - 64
				ciphertext = encrypted_box_bytes[:length]
				check_sum = encrypted_box_bytes[length:]
				sum, err = userlib.HMACEval(hmac_key[:16], ciphertext)
				if err != nil {
					return errors.New("unable to generate a checksum for encrypted box")
				}

				equal = userlib.HMACEqual(check_sum, sum)
				if !equal {
					return errors.New("lockbox integrity is compromised...data is corrupted")
				}

				plaintext = userlib.SymDec(symenc_key[:16], ciphertext)
				err = json.Unmarshal(plaintext, &box)
				if err != nil {
					return errors.New("corrupted json unmarshal of lockbox")
				}

				// Fill fields of file_data from updated box
				file_data.File_symenc_key = box.File_encrypt_key[:userlib.AESBlockSizeBytes]
				file_data.File_hmac_key = box.File_encrypt_key[userlib.AESBlockSizeBytes:]

				file_data.Node_symenc_key = box.Node_encrypt_key[:userlib.AESBlockSizeBytes]
				file_data.Node_hmac_key = box.Node_encrypt_key[userlib.AESBlockSizeBytes:]

				file_data.Datastore_key = box.File_location

				userdata.Files[storage_key] = file_data
				_, file_exists := userlib.DatastoreGet(file_data.Datastore_key)
				if !file_exists {
					return errors.New("file does not exist even after pulling info from most recent version of box")
				}
			}
		}

		// We want to retrieve the file so we can set owner appropriately then we can overwrite everything else
		file_bytes, exists := userlib.DatastoreGet(file_data.Datastore_key)
		if !exists {
			return errors.New("unable to fetch existing file from Datastore")
		}

		// Decrypt and verify integrity of file
		length = len(file_bytes) - 64
		ciphertext = file_bytes[:length]
		check_sum = file_bytes[length:]
		sum, err = userlib.HMACEval(file_data.File_hmac_key[:16], ciphertext)
		if err != nil {
			return errors.New("unable to generate a checksum through HMACEval")
		}

		equal = userlib.HMACEqual(check_sum, sum)
		if !equal {
			return errors.New("integrity is compromised...data is corrupted")
		}

		plaintext = userlib.SymDec(file_data.File_symenc_key[:16], ciphertext)
		err = json.Unmarshal(plaintext, &file)
		if err != nil {
			return errors.New("corrupted JSON Unmarshal")
		}

		// There is already an existing file Owner so we should not overwrite that
		owner = file.Owner

	} else {
		// If there is no existing file in that namespace, we generate owner field based on userdata
		owner, err = uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
		if err != nil {
			return errors.New("unable to derive uuid associated with username")
		}

		// Generate a new UUID for storing File in Datastore
		file_data.Datastore_key = uuid.New()

		// Generate keys for encryption of file itself
		file_data.File_symenc_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.AESBlockSizeBytes)), uint32(userlib.AESBlockSizeBytes))
		file_data.File_hmac_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.HashSizeBytes)), uint32(userlib.HashSizeBytes))

		// Generate keys for encryption of content nodes
		file_data.Node_symenc_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.AESBlockSizeBytes)), uint32(userlib.AESBlockSizeBytes))
		file_data.Node_hmac_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.HashSizeBytes)), uint32(userlib.HashSizeBytes))

	}

	// // Generate a new UUID for storing File in Datastore
	// file_data.Datastore_key = uuid.New()

	// // Generate keys for encryption of file itself
	// file_data.File_symenc_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.AESBlockSizeBytes)), uint32(userlib.AESBlockSizeBytes))
	// file_data.File_hmac_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.HashSizeBytes)), uint32(userlib.HashSizeBytes))

	// // Generate keys for encryption of content nodes
	// file_data.Node_symenc_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.AESBlockSizeBytes)), uint32(userlib.AESBlockSizeBytes))
	// file_data.Node_hmac_key = userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.HashSizeBytes)), uint32(userlib.HashSizeBytes))

	// Initialize a new node and set fields
	var node Node_Content
	node.Content = content
	node.Next = uuid.Nil

	// Generate new Datastore key
	ds_node_uuid := uuid.New()

	// Marshal node, encrypt, and store in Datastore
	node_bytes, err := json.Marshal(node)
	if err != nil {
		return errors.New("unable to Marshal node")
	}

	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	node_encrypt := userlib.SymEnc(file_data.Node_symenc_key[:16], IV, node_bytes)
	check_sum, err = userlib.HMACEval(file_data.Node_hmac_key[:16], node_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	node_encrypt_hmac := append(node_encrypt, check_sum...)
	userlib.DatastoreSet(ds_node_uuid, node_encrypt_hmac)

	// Set attributes of File
	file.Start = ds_node_uuid
	file.End = ds_node_uuid
	file.Content_length = 1
	file.Owner = owner

	// Marshal, encrypt, and store file in Datastore
	file_bytes, err := json.Marshal(file)
	if err != nil {
		return errors.New("cannot Marshal File struct into a JSON byte array representation")
	}

	IV = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	file_encrypt := userlib.SymEnc(file_data.File_symenc_key[:16], IV, file_bytes)
	check_sum, err = userlib.HMACEval(file_data.File_hmac_key[:16], file_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	file_encrypt_hmac := append(file_encrypt, check_sum...)
	userdata.Files[storage_key] = file_data
	userlib.DatastoreSet(file_data.Datastore_key, file_encrypt_hmac)

	// Update userdata in Datastore
	user_bytes, err := json.Marshal(userdata)
	if err != nil {
		return errors.New("cannot Marshal User struct into a JSON byte array representation")
	}

	IV = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	user_encrypt := userlib.SymEnc(userdata.SymEnc_key[:16], IV, user_bytes)
	check_sum, err = userlib.HMACEval(userdata.HMAC_key[:16], user_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	user_encrypt_hmac := append(user_encrypt, check_sum...)
	ds_key_uuid, err = uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return errors.New("cannot convert Datastore_key byte array into a UUID")
	}

	userlib.DatastoreSet(ds_key_uuid, user_encrypt_hmac)
	return nil
}

/*
	Given a filename in the personal namespace of the caller, this
	function appends the given content to the end of the corresponding file
*/
func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Pull most recent version of userdata from Datastore, decrypt, and verify integrity
	ds_key_uuid, err := uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return errors.New("unable to convert userdata's datastore key to a uuid")
	}

	loaded_user_bytes, exists := userlib.DatastoreGet(ds_key_uuid)
	if !exists {
		return errors.New("userdata does not exist in Datastore")
	}

	length := len(loaded_user_bytes) - 64
	ciphertext := loaded_user_bytes[:length]
	check_sum := loaded_user_bytes[length:]
	sum, err := userlib.HMACEval(userdata.HMAC_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum for userdata through HMACEval")
	}

	equal := userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("userdata integrity is compromised...data is corrupted")
	}

	plaintext := userlib.SymDec(userdata.SymEnc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return errors.New("corrupted JSON Unmarshal")
	}

	// Primary key for storing File_Data objects and Lockbox_Data objects in userdata maps
	storage_key, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("unable to create storage key for new file")
	}

	// Check if this file_data of this name exists in the namespace
	file_data, exists := userdata.Files[storage_key]
	if !exists {
		return errors.New("the given filename does not exist in the personal file namespace of the caller")
	}

	// Pull most recent version of lockbox from Datastore if necessary
	var file File
	file_bytes, file_exists := userlib.DatastoreGet(file_data.Datastore_key)
	if len(userdata.Lockboxes[storage_key]) > 0 {
		encrypted_box_bytes, box_exists := userlib.DatastoreGet(userdata.Lockboxes[storage_key][0].Location)
		if !file_exists && !box_exists {
			return errors.New("revoked users cannot access deleted lockbox or file")
		}

		if !file_exists && box_exists && len(userdata.Lockboxes[storage_key]) > 0 {
			// Retrieve most recent version of lockbox (updated through RevokeAcess) and update userdata.Files
			var box Lockbox

			// Separate encryption keys used for lockbox
			symenc_key := userdata.Lockboxes[storage_key][0].Encrypt_keys[:userlib.AESBlockSizeBytes]
			hmac_key := userdata.Lockboxes[storage_key][0].Encrypt_keys[userlib.AESBlockSizeBytes:]

			// Decrypt and verify integrity of encrypted lockbox
			length = len(encrypted_box_bytes) - 64
			ciphertext = encrypted_box_bytes[:length]
			check_sum = encrypted_box_bytes[length:]
			sum, err = userlib.HMACEval(hmac_key[:16], ciphertext)
			if err != nil {
				return errors.New("unable to generate a checksum for encrypted box")
			}

			equal = userlib.HMACEqual(check_sum, sum)
			if !equal {
				return errors.New("lockbox integrity is compromised...data is corrupted")
			}

			plaintext = userlib.SymDec(symenc_key[:16], ciphertext)
			err = json.Unmarshal(plaintext, &box)
			if err != nil {
				return errors.New("corrupted json unmarshal of lockbox")
			}

			// Fill fields of file_data from updated box
			file_data.File_symenc_key = box.File_encrypt_key[:userlib.AESBlockSizeBytes]
			file_data.File_hmac_key = box.File_encrypt_key[userlib.AESBlockSizeBytes:]

			file_data.Node_symenc_key = box.Node_encrypt_key[:userlib.AESBlockSizeBytes]
			file_data.Node_hmac_key = box.Node_encrypt_key[userlib.AESBlockSizeBytes:]

			file_data.Datastore_key = box.File_location

			userdata.Files[storage_key] = file_data

			// Attempt to retrieve file again
			file_bytes, file_exists = userlib.DatastoreGet(file_data.Datastore_key)
			if !file_exists {
				return errors.New("file does not exist even after pulling info from most recent version of box")
			}
		}
	}
	// Decrypt and verify integrity of file
	length = len(file_bytes) - 64
	ciphertext = file_bytes[:length]
	check_sum = file_bytes[length:]
	sum, err = userlib.HMACEval(file_data.File_hmac_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	equal = userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("integrity is compromised...data is corrupted")
	}

	plaintext = userlib.SymDec(file_data.File_symenc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &file)
	if err != nil {
		return errors.New("corrupted JSON Unmarshal")
	}

	// Declare two nodes
	var new_node, last_node Node_Content
	new_node.Content = content
	last_node_bytes, exists := userlib.DatastoreGet(file.End)
	if !exists {
		return errors.New("last node added to file does not exist in datastore")
	}

	// Decrypt and verify integrity of last_node
	length = len(last_node_bytes) - 64
	ciphertext = last_node_bytes[:length]
	check_sum = last_node_bytes[length:]
	sum, err = userlib.HMACEval(file_data.Node_hmac_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	equal = userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("integrity is compromised...data is corrupted")
	}

	plaintext = userlib.SymDec(file_data.Node_symenc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &last_node)
	if err != nil {
		return errors.New("corrupted JSON Unmarshal")
	}

	// Generate a random UUID for new node to store in Datastore
	new_node_uuid := uuid.New()
	last_node.Next = new_node_uuid

	// Marshal node and encrypt before storing in Datastore
	new_node_bytes, err := json.Marshal(new_node)
	if err != nil {
		return errors.New("unable to Marshal node")
	}

	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	new_node_encrypt := userlib.SymEnc(file_data.Node_symenc_key[:16], IV, new_node_bytes)
	check_sum, err = userlib.HMACEval(file_data.Node_hmac_key[:16], new_node_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	new_node_encrypt_mac := append(new_node_encrypt, check_sum...)
	userlib.DatastoreSet(new_node_uuid, new_node_encrypt_mac)

	// Re-encrypt and upload last_node to Datastore
	last_node_bytes, err = json.Marshal(last_node)
	if err != nil {
		return errors.New("unable to Marshal node")
	}

	IV = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	last_node_encrypt := userlib.SymEnc(file_data.Node_symenc_key[:16], IV, last_node_bytes)
	check_sum, err = userlib.HMACEval(file_data.Node_hmac_key[:16], last_node_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	last_node_encrypt_mac := append(last_node_encrypt, check_sum...)
	userlib.DatastoreSet(file.End, last_node_encrypt_mac)

	// Update file fields and then store in Datastore
	file.End = new_node_uuid
	file.Content_length = file.Content_length + 1
	file_bytes, err = json.Marshal(file)
	if err != nil {
		return errors.New("unable to Marshal node")
	}

	IV = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	file_encrypt := userlib.SymEnc(file_data.File_symenc_key[:16], IV, file_bytes)
	check_sum, err = userlib.HMACEval(file_data.File_hmac_key[:16], file_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	file_encrypt_mac := append(file_encrypt, check_sum...)
	userlib.DatastoreSet(file_data.Datastore_key, file_encrypt_mac)
	return nil

}

/*
	Given a filename in the personal namespace of the caller, this function
	downloads and returns the content of the corresponding file
*/
func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Pull most recent version of userdata from Datastore, decrypt, and verify integrity
	ds_key_uuid, err := uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return nil, errors.New("unable to convert userdata's datastore key to a uuid")
	}

	loaded_user_bytes, exists := userlib.DatastoreGet(ds_key_uuid)
	if !exists {
		return nil, errors.New("userdata does not exist in Datastore")
	}

	length := len(loaded_user_bytes) - 64
	ciphertext := loaded_user_bytes[:length]
	check_sum := loaded_user_bytes[length:]
	sum, err := userlib.HMACEval(userdata.HMAC_key[:16], ciphertext)
	if err != nil {
		return nil, errors.New("unable to generate a checksum for userdata through HMACEval")
	}

	equal := userlib.HMACEqual(check_sum, sum)
	if !equal {
		return nil, errors.New("userdata integrity is compromised...data is corrupted")
	}

	plaintext := userlib.SymDec(userdata.SymEnc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return nil, errors.New("corrupted JSON Unmarshal")
	}

	// Rederive storage_key that maps to this file
	storage_key, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, errors.New("unable to derivate uuid from storage key")
	}

	// Check if this file of this name exists in the namespace
	file_data, exists := userdata.Files[storage_key]
	if !exists {
		return nil, errors.New("the given filename does not exist in the personal file namespace of the caller")
	}

	// Retrieve file from Datastore using file_data information and decrypt
	var file File
	file_bytes, file_exists := userlib.DatastoreGet(file_data.Datastore_key)

	// If userdata has lockboxes for this file, proceed
	if len(userdata.Lockboxes[storage_key]) > 0 {
		encrypted_box_bytes, box_exists := userlib.DatastoreGet(userdata.Lockboxes[storage_key][0].Location)
		if !file_exists && !box_exists {
			return nil, errors.New("revoked users cannot access deleted lockbox or file")
		}

		if !file_exists && box_exists && len(userdata.Lockboxes[storage_key]) > 0 {
			// Retrieve most recent version of lockbox (updated through RevokeAcess) and update userdata.Files
			var box Lockbox
			symenc_key := userdata.Lockboxes[storage_key][0].Encrypt_keys[:userlib.AESBlockSizeBytes]
			hmac_key := userdata.Lockboxes[storage_key][0].Encrypt_keys[userlib.AESBlockSizeBytes:]

			// Decrypt and verify integrity of encrypted lockbox
			length = len(encrypted_box_bytes) - 64
			ciphertext = encrypted_box_bytes[:length]
			check_sum = encrypted_box_bytes[length:]
			sum, err = userlib.HMACEval(hmac_key[:16], ciphertext)
			if err != nil {
				return nil, errors.New("unable to generate a checksum for encrypted box")
			}

			equal = userlib.HMACEqual(check_sum, sum)
			if !equal {
				return nil, errors.New("lockbox integrity is compromised...data is corrupted")
			}

			plaintext = userlib.SymDec(symenc_key[:16], ciphertext)
			err = json.Unmarshal(plaintext, &box)
			if err != nil {
				return nil, errors.New("corrupted json unmarshal of lockbox")
			}

			// Fill fields of file_data from updated box
			file_data.File_symenc_key = box.File_encrypt_key[:userlib.AESBlockSizeBytes]
			file_data.File_hmac_key = box.File_encrypt_key[userlib.AESBlockSizeBytes:]

			file_data.Node_symenc_key = box.Node_encrypt_key[:userlib.AESBlockSizeBytes]
			file_data.Node_hmac_key = box.Node_encrypt_key[userlib.AESBlockSizeBytes:]

			file_data.Datastore_key = box.File_location

			userdata.Files[storage_key] = file_data
			file_bytes, file_exists = userlib.DatastoreGet(file_data.Datastore_key)
			if !file_exists {
				return nil, errors.New("file does not exist even after pulling info from most recent version of box")
			}
		}
	}

	// Decrypt and verify integrity of file
	length = len(file_bytes) - 64
	ciphertext = file_bytes[:length]
	check_sum = file_bytes[length:]
	sum, err = userlib.HMACEval(file_data.File_hmac_key[:16], ciphertext)
	if err != nil {
		return nil, errors.New("unable to generate a checksum through HMACEval")
	}

	equal = userlib.HMACEqual(check_sum, sum)
	if !equal {
		return nil, errors.New("integrity is compromised...data is corrupted")
	}

	plaintext = userlib.SymDec(file_data.File_symenc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &file)
	if err != nil {
		return nil, errors.New("corrupted JSON Unmarshal")
	}

	// Traverse through all content nodes associated with this file
	curr_uuid := file.Start
	for i := 0; i < file.Content_length; i++ {
		var curr Node_Content

		// Retrieve node from Datastore starting with File.Start
		node_bytes, exists := userlib.DatastoreGet(curr_uuid)
		if !exists {
			return nil, errors.New("this node does not exist in Datastore")
		}

		// Decrypt the node and verify integrity
		length := len(node_bytes) - 64
		ciphertext := node_bytes[:length]
		check_sum := node_bytes[length:]
		sum, err := userlib.HMACEval(file_data.Node_hmac_key[:16], ciphertext)
		if err != nil {
			return nil, errors.New("unable to generate a checksum through HMACEval")
		}

		equal := userlib.HMACEqual(check_sum, sum)
		if !equal {
			return nil, errors.New("integrity is compromised...data is corrupted")
		}

		plaintext := userlib.SymDec(file_data.Node_symenc_key[:16], ciphertext)
		err = json.Unmarshal(plaintext, &curr)
		if err != nil {
			return nil, errors.New("corrupted JSON Unmarshal")
		}

		// Append it to content before moving to next node
		content = append(content, curr.Content...)
		curr_uuid = curr.Next
	}

	return content, err
}

/*
	Given a filename in the personal namespace of the caller, this function creates a secure file share invitation that contains
	all of the information required for recipientUsername to take the actions detailed in Sharing and Revoking on the corresponding file
*/
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr userlib.UUID, err error) {
	// Pull most recent version of userdata from Datastore, decrypt, and verify integrity
	ds_key_uuid, err := uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return uuid.Nil, errors.New("unable to convert userdata's datastore key to a uuid")
	}

	// Decrypt most recent version of userdata and verify integrity
	loaded_user_bytes, exists := userlib.DatastoreGet(ds_key_uuid)
	if !exists {
		return uuid.Nil, errors.New("userdata does not exist in Datastore")
	}

	length := len(loaded_user_bytes) - 64
	ciphertext := loaded_user_bytes[:length]
	check_sum := loaded_user_bytes[length:]
	sum, err := userlib.HMACEval(userdata.HMAC_key[:16], ciphertext)
	if err != nil {
		return uuid.Nil, errors.New("unable to generate a checksum for userdata through HMACEval")
	}

	equal := userlib.HMACEqual(check_sum, sum)
	if !equal {
		return uuid.Nil, errors.New("userdata integrity is compromised...data is corrupted")
	}

	plaintext := userlib.SymDec(userdata.SymEnc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return uuid.Nil, errors.New("corrupted JSON Unmarshal")
	}

	// Derive storage key for this file in sender namespace
	storage_key, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return uuid.Nil, errors.New("unable to create storage key for new file")
	}

	// Verify this file exists in sender namespace
	file_data, exists := userdata.Files[storage_key]
	if !exists {
		return uuid.Nil, errors.New("given filename does not exist in the personal file namespace of the caller")
	}

	// Check existence of recipient
	recipient_key, _ := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	_, exists = userlib.KeystoreGet(recipient_key.String())
	if !exists {
		return uuid.Nil, errors.New("recipient does not exist")
	}

	// Retrieve recipient's public key from Keystore and verify its existence
	recipient_uuid, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	if err != nil {
		return uuid.Nil, errors.New("unable to derive uuid for username using hash and frombytes method")
	}

	recipient_public_key, exists := userlib.KeystoreGet(recipient_uuid.String())
	if !exists {
		return uuid.Nil, errors.New("sender's rsa public key doesn't exist in keystore")
	}

	// Retrieve file from Datastore to identify owner, and based off of that we can take one of two possible directions
	var file File
	file_bytes, exists := userlib.DatastoreGet(userdata.Files[storage_key].Datastore_key)
	if !exists {
		return uuid.Nil, errors.New("file does not exist in Datastore")
	}

	// Decrypt and verify integrity of file_bytes
	length = len(file_bytes) - 64
	ciphertext = file_bytes[:length]
	check_sum = file_bytes[length:]
	sum, err = userlib.HMACEval(file_data.File_hmac_key[:16], ciphertext)
	if err != nil {
		return uuid.Nil, errors.New("unable to generate a checksum through HMACEval")
	}

	equal = userlib.HMACEqual(check_sum, sum)
	if !equal {
		return uuid.Nil, errors.New("integrity is compromised...data is corrupted")
	}

	plaintext = userlib.SymDec(file_data.File_symenc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &file)
	if err != nil {
		return uuid.Nil, errors.New("corrupted JSON Unmarshal")
	}

	user_uuid, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		return uuid.Nil, errors.New("unable to ")
	}
	owner := file.Owner
	if owner != user_uuid {
		// If the user is not the owner, then we do not create a lockbox
		data := userdata.Lockboxes[storage_key][0]

		// Since lockbox is already encrypted by the keys stored in Lockbox_Data, we just need to encrypt the keys with assymetric encryption
		ciphered_keys, err := userlib.PKEEnc(recipient_public_key, data.Encrypt_keys)
		if err != nil {
			return uuid.Nil, err
		}

		// Generate signature using sender's private Digital Sign Key
		sign, err := userlib.DSSign(userdata.DSSignKey, ciphered_keys)
		if err != nil {
			return uuid.Nil, errors.New("unable to generate digital signature for lockbox")
		}

		// Append ciphered_keys and 256-bit signature
		cipher_and_sign := append(ciphered_keys, sign...)

		// Create new invite with box_uuid and keys encrypted under assymetric encryption
		invite := Invitation{data.Location, cipher_and_sign}

		// Marshal invite struct and store in Datastore
		invite_uuid := uuid.New()
		invite_bytes, err := json.Marshal(invite)
		if err != nil {
			return uuid.Nil, errors.New("unable to marshal invitiation struct for sending invite")
		}

		userlib.DatastoreSet(invite_uuid, invite_bytes)
		return invite_uuid, nil

	} else {
		// If the user is the owner of the file, create a new lockbox

		// Append keys for encrypting files and nodes
		file_encrypt_keys := append(file_data.File_symenc_key, file_data.File_hmac_key...)
		node_encrypt_keys := append(file_data.Node_symenc_key, file_data.Node_hmac_key...)

		// Retrieve location for file from file_data
		file_location := file_data.Datastore_key

		// Initialize and declare a new lockbox containing file, node encryption keys, uuid pointing to file in Datastore
		box := Lockbox{file_encrypt_keys, node_encrypt_keys, file_location}

		// Marshal lockbox before hybrid encryption scheme
		box_bytes, err := json.Marshal(box)
		if err != nil {
			return uuid.Nil, errors.New("unable to Marshal new lockbox")
		}

		// Hybrid encryption

		// First, derive keys using symmetric encryption
		symenc_key := userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.AESBlockSizeBytes)), uint32(userlib.AESBlockSizeBytes))
		hmac_key := userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.HashSizeBytes)), uint32(userlib.HashSizeBytes))

		// Append two keys together
		encrypt_hmac_keys := append(symenc_key, hmac_key...)

		// Encrypt Marshaled lockbox under a symmetric encryption scheme
		IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		box_encrypt := userlib.SymEnc(symenc_key[:16], IV, box_bytes)
		check_sum, err = userlib.HMACEval(hmac_key[:16], box_encrypt)
		if err != nil {
			return uuid.Nil, errors.New("unable to generate a checksum through HMACEval")
		}

		// Concatenate encrypted box and hmac
		box_encrypt_hmac := append(box_encrypt, check_sum...)

		// After encrypting lockbox under symmetric encryption, encrypt the keys used under assymetric encryption
		// Use the recepient's public key to encrypt the appended keys
		ciphered_keys, err := userlib.PKEEnc(recipient_public_key, encrypt_hmac_keys)
		if err != nil {
			return uuid.Nil, err
		}

		// Generate signature using sender's private Digital Sign Key
		sign, err := userlib.DSSign(userdata.DSSignKey, ciphered_keys)
		if err != nil {
			return uuid.Nil, errors.New("unable to generate digital signature for lockbox")
		}

		// Append ciphered_keys and 256-bit signature
		cipher_and_sign := append(ciphered_keys, sign...)

		// Generate a uuid that will point to symmetric encrypted box
		box_uuid := uuid.New()

		// Store encrypted box in Datastore
		userlib.DatastoreSet(box_uuid, box_encrypt_hmac)

		// Create new invite with box_uuid and keys encrypted under assymetric encryption
		invite := Invitation{box_uuid, cipher_and_sign}

		// Marshal invite struct and store in Datastore
		invite_uuid := uuid.New()
		invite_bytes, err := json.Marshal(invite)
		if err != nil {
			return uuid.Nil, errors.New("unable to marshal invitiation struct for sending invite")
		}

		userlib.DatastoreSet(invite_uuid, invite_bytes)

		// Append new box uuid to sender's map of lockboxes
		userdata.Lockboxes[storage_key] = append(userdata.Lockboxes[storage_key], Lockbox_Data{box_uuid, encrypt_hmac_keys, recipientUsername})

		// Marshal userdata, encrypt, and store in Datastore
		user_bytes, err := json.Marshal(userdata)
		if err != nil {
			return uuid.Nil, errors.New("cannot Marshal updated user struct")
		}

		IV = userlib.RandomBytes(userlib.AESBlockSizeBytes)
		user_encrypt := userlib.SymEnc(userdata.SymEnc_key[:16], IV, user_bytes)
		check_sum, err = userlib.HMACEval(userdata.HMAC_key[:16], user_encrypt)
		if err != nil {
			return uuid.Nil, errors.New("unable to generate a checksum through HMACEval")
		}

		user_encrypt_hmac := append(user_encrypt, check_sum...)
		user_uuid, err := uuid.FromBytes(userdata.Datastore_key)
		if err != nil {
			return uuid.Nil, errors.New("cannot convert Datastore_key byte array into a UUID")
		}

		userlib.DatastoreSet(user_uuid, user_encrypt_hmac)

		// Return pointer to invite
		return invite_uuid, nil
	}
}

/*
	Accepts the secure file share invitation created by senderUsername and located at invitationPtr
	in Datastore by giving the corresponding file a name of filename in the caller’s personal namespace
*/
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Pull most recent version of userdata from Datastore, decrypt, and verify integrity
	ds_key_uuid, err := uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return errors.New("unable to convert userdata's datastore key to a uuid")
	}

	loaded_user_bytes, exists := userlib.DatastoreGet(ds_key_uuid)
	if !exists {
		return errors.New("userdata does not exist in Datastore")
	}

	length := len(loaded_user_bytes) - 64
	ciphertext := loaded_user_bytes[:length]
	check_sum := loaded_user_bytes[length:]
	sum, err := userlib.HMACEval(userdata.HMAC_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum for userdata through HMACEval")
	}

	equal := userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("userdata integrity is compromised...data is corrupted")
	}

	plaintext := userlib.SymDec(userdata.SymEnc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return errors.New("corrupted JSON Unmarshal")
	}

	// Check existence of sender
	sender_key, _ := uuid.FromBytes(userlib.Hash([]byte(senderUsername))[:16])
	_, exists = userlib.KeystoreGet(sender_key.String())
	if !exists {
		return errors.New("sender does not exist")
	}

	// Determine if userdata already has file with filename in their personal namespace
	storage_key, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("unable to create storage key for new file")
	}

	_, exists = userdata.Files[storage_key]
	if exists {
		return errors.New("a file with this name already exists in the user namespace")
	}

	// Retrieve Marshaled invitation struct from Datastore
	invite_bytes, exists := userlib.DatastoreGet(invitationPtr)
	if !exists {
		return errors.New("unable to retrieve invititation struct from Datastore")
	}

	// Unmarshal invite struct to retrieve the pointer to the lockbox and the keys encrypted with an assymetric scheme
	var invite Invitation
	err = json.Unmarshal(invite_bytes, &invite)
	if err != nil {
		return errors.New("unable to unmarshal invite_bytes into an invitation struct")
	}

	// Separate ciphered keys and signature from invite
	length = len(invite.Asymmenc_keys) - 256
	ciphered_keys := invite.Asymmenc_keys[:length]
	sign := invite.Asymmenc_keys[length:]

	// Derive and retrieve sender's public verification key
	hash := userlib.Hash([]byte(senderUsername))
	sender_uuid, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return errors.New("An error occurred while generating a UUID: " + err.Error())
	}

	source_key_bytes, err := json.Marshal(sender_uuid)
	if err != nil {
		return errors.New("unable to marshal source_key uuid")
	}

	sender_verify_uuid, err := userlib.HashKDF(source_key_bytes[:16], []byte("verify"))
	if err != nil {
		return errors.New("cannot derive a verify_key using source_key_bytes and hashkdf")
	}

	sender_verify_key, exists := userlib.KeystoreGet(string(sender_verify_uuid))
	if !exists {
		return errors.New("sender's public verify key not in keystore")
	}

	// Verify that sender created invite
	err = userlib.DSVerify(sender_verify_key, ciphered_keys, sign)
	if err != nil {
		return errors.New("cannot verify that sender created invitation")
	}

	// Decrypt ciphered_keys using userdata's private RSA key
	decrypt_keys, err := userlib.PKEDec(userdata.PKEDecKey, ciphered_keys)
	if err != nil {
		return errors.New("cannot decrypt ciphered_keys needed to decrypt lockbox")
	}

	// Separate decrypted keys into the symmetric encryption key and hmac key
	symenc_key := decrypt_keys[:userlib.AESBlockSizeBytes]
	hmac_key := decrypt_keys[userlib.AESBlockSizeBytes:]
	encrypt_hmac_keys := append(symenc_key, hmac_key...)

	// Retrieve encrypted lockbox from Datastore
	var box Lockbox
	encrypted_box_bytes, exists := userlib.DatastoreGet(invite.Lockbox_key)
	if !exists {
		return errors.New("encrypted lockbox does not exist in Datastore")
	}

	// Decrypt and verify integrity of encrypted lockbox
	length = len(encrypted_box_bytes) - 64
	ciphertext = encrypted_box_bytes[:length]
	check_sum = encrypted_box_bytes[length:]
	sum, err = userlib.HMACEval(hmac_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum for encrypted box")
	}

	equal = userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("lockbox integrity is compromised...data is corrupted")
	}

	plaintext = userlib.SymDec(symenc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &box)
	if err != nil {
		return errors.New("corrupted json unmarshal of lockbox")
	}

	// Create storage key for userdata
	storage_key, err = uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("unable to create storage key for new file shared by sender")
	}

	// Initialize and declare file_data for this file
	var file_data File_Data

	// Fill fields of file_data
	file_data.File_symenc_key = box.File_encrypt_key[:userlib.AESBlockSizeBytes]
	file_data.File_hmac_key = box.File_encrypt_key[userlib.AESBlockSizeBytes:]

	file_data.Node_symenc_key = box.Node_encrypt_key[:userlib.AESBlockSizeBytes]
	file_data.Node_hmac_key = box.Node_encrypt_key[userlib.AESBlockSizeBytes:]

	file_data.Datastore_key = box.File_location

	// Map storage key to file_data that contains information on how to retrieve file and keys to decrypt it and node structs
	userdata.Files[storage_key] = file_data
	userdata.Lockboxes[storage_key] = append(userdata.Lockboxes[storage_key], Lockbox_Data{invite.Lockbox_key, encrypt_hmac_keys, senderUsername})

	// Update userdata in Datastore
	user_bytes, err := json.Marshal(userdata)
	if err != nil {
		return errors.New("cannot Marshal User struct into a JSON byte array representation")
	}

	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	user_encrypt := userlib.SymEnc(userdata.SymEnc_key[:16], IV, user_bytes)
	check_sum, err = userlib.HMACEval(userdata.HMAC_key[:16], user_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	user_encrypt_hmac := append(user_encrypt, check_sum...)
	ds_key_uuid, err = uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return errors.New("cannot convert Datastore_key byte array into a UUID")
	}

	userlib.DatastoreSet(ds_key_uuid, user_encrypt_hmac)
	return nil
}

/*
	Given a filename in the personal namespace of the caller, this function revokes access to the
	corresponding file from recipientUsername and any other users with whom recipientUsernamehas shared the file
*/
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Pull most recent version of userdata from Datastore, decrypt, and verify integrity
	ds_key_uuid, err := uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return errors.New("unable to convert userdata's datastore key to a uuid")
	}

	loaded_user_bytes, exists := userlib.DatastoreGet(ds_key_uuid)
	if !exists {
		return errors.New("userdata does not exist in Datastore")
	}

	length := len(loaded_user_bytes) - 64
	ciphertext := loaded_user_bytes[:length]
	check_sum := loaded_user_bytes[length:]
	sum, err := userlib.HMACEval(userdata.HMAC_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum for userdata through HMACEval")
	}

	equal := userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("userdata integrity is compromised...data is corrupted")
	}

	plaintext := userlib.SymDec(userdata.SymEnc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &userdata)
	if err != nil {
		return errors.New("corrupted JSON Unmarshal")
	}

	// Derive storage key to check for existence of file in caller's namespace
	storage_key, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("unable to create storage key for new file")
	}

	// Check if this file of this name exists in the namespace
	_, exists = userdata.Files[storage_key]
	if !exists {
		return errors.New("file does not exist in caller's namespace")
	}

	// Iterate through usedata.Lockboxes[storage_key]
	// See if given filename is shared with recipientUser
	var username string
	exists = false
	for i := 0; i < len(userdata.Lockboxes[storage_key]); i += 1 {
		username = userdata.Lockboxes[storage_key][i].Shared_user
		if username == recipientUsername {
			exists = true
			break
		}
	}

	if !exists {
		return errors.New("the given filename is not currently shared with the recipient")
	}

	// Retrieve file_data for this filename
	file_data, exists := userdata.Files[storage_key]
	if !exists {
		return errors.New("the file_data for given filename does not exist in userdata's Files")
	}

	// Retrieve file for this filename from Datastore
	file_bytes, exists := userlib.DatastoreGet(file_data.Datastore_key)
	if !exists {
		return errors.New("unable to fetch file (using file_data datastore key) from Datastore")
	}

	// Decrypt and verify integrity of file_bytes
	var file File
	length = len(file_bytes) - 64
	ciphertext = file_bytes[:length]
	check_sum = file_bytes[length:]
	sum, err = userlib.HMACEval(file_data.File_hmac_key[:16], ciphertext)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	equal = userlib.HMACEqual(check_sum, sum)
	if !equal {
		return errors.New("integrity is compromised...data is corrupted")
	}

	plaintext = userlib.SymDec(file_data.File_symenc_key[:16], ciphertext)
	err = json.Unmarshal(plaintext, &file)
	if err != nil {
		return errors.New("corrupted JSON Unmarshal")
	}

	// Create new keys for re-encryption of file and node objects
	new_ds_key := uuid.New()
	new_file_symenc_key := userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.AESBlockSizeBytes)), uint32(userlib.AESBlockSizeBytes))
	new_file_hmac_key := userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.HashSizeBytes)), uint32(userlib.HashSizeBytes))
	new_node_symenc_key := userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.AESBlockSizeBytes)), uint32(userlib.AESBlockSizeBytes))
	new_node_hmac_key := userlib.Argon2Key([]byte(uuid.New().String()), []byte(userlib.RandomBytes(userlib.HashSizeBytes)), uint32(userlib.HashSizeBytes))

	next_uuid := uuid.New()
	// Iterate through all nodes for this file and re-encrypt with new node keys
	curr_uuid := file.Start
	// var new_next_uuid userlib.UUID
	for i := 0; i < file.Content_length; i++ {
		var curr Node_Content
		// Retrieve node from Datastore
		node_bytes, exists := userlib.DatastoreGet(curr_uuid)
		if !exists {
			return errors.New("this node does not exist in Datastore")
		}

		// Decrypt the node and verify integrity
		length := len(node_bytes) - 64
		ciphertext := node_bytes[:length]
		check_sum := node_bytes[length:]
		sum, err := userlib.HMACEval(file_data.Node_hmac_key[:16], ciphertext)
		if err != nil {
			return errors.New("unable to generate a checksum through HMACEval")
		}

		equal := userlib.HMACEqual(check_sum, sum)
		if !equal {
			return errors.New("integrity is compromised...data is corrupted")
		}

		plaintext := userlib.SymDec(file_data.Node_symenc_key[:16], ciphertext)
		err = json.Unmarshal(plaintext, &curr)
		if err != nil {
			return errors.New("corrupted JSON Unmarshal")
		}

		// var next_uuid userlib.UUID
		curr_uuid = curr.Next
		curr_node_key := next_uuid

		if curr.Next != uuid.Nil {
			next_uuid = uuid.New()
			curr.Next = next_uuid
		}

		// Derive new uuid for next node and set curr.Next to it
		// var new_node_uuid userlib.UUID
		// if i != 0 {
		// 	new_node_uuid = new_next_uuid
		// } else if i != file.Content_length-1 {
		// 	new_next_uuid := uuid.New()
		// 	curr.Next = new_next_uuid
		// } else {
		// 	curr.Next = uuid.Nil
		// }

		// Re-encrypt node with new keys and derive new Datastore key for its storage
		// Marshal node into byte representation
		curr_bytes, err := json.Marshal(curr)
		if err != nil {
			return errors.New("unable to Marshal node")
		}

		IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		curr_node_encrypt := userlib.SymEnc(new_node_symenc_key[:16], IV, curr_bytes)
		check_sum, err = userlib.HMACEval(new_node_hmac_key[:16], curr_node_encrypt)
		if err != nil {
			return errors.New("unable to generate a checksum through HMACEval")
		}

		// Append re-encrypted current node and check_sum and store in Datastore with new key
		curr_node_encrypt_mac := append(curr_node_encrypt, check_sum...)

		// If we are at the start node, make sure to re-set file.Start
		if i == 0 && file.Content_length > 1 {
			// new_node_uuid := uuid.New()
			// file.Start = new_node_uuid
			// userlib.DatastoreSet(new_node_uuid, curr_node_encrypt_mac)
			file.Start = curr_node_key
			userlib.DatastoreSet(curr_node_key, curr_node_encrypt_mac)
		} else if i == 0 && file.Content_length == 1 {
			// If there is only one node in the file, set file.Start and file.End
			// new_node_uuid := uuid.New()
			file.Start = curr_node_key
			file.End = curr_node_key
			userlib.DatastoreSet(curr_node_key, curr_node_encrypt_mac)
		} else {
			// Otherwise, use previously generated uuid to store encrypted node
			userlib.DatastoreSet(curr_node_key, curr_node_encrypt_mac)
			if i == file.Content_length-1 {
				file.End = curr_node_key
			}
		}
	}

	// Re-encrypt the file itself using the new keys
	file_bytes, err = json.Marshal(file)
	if err != nil {
		return errors.New("unable to Marshal node")
	}

	IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	file_encrypt := userlib.SymEnc(new_file_symenc_key[:16], IV, file_bytes)
	check_sum, err = userlib.HMACEval(new_file_hmac_key[:16], file_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	// Append re-encrypted current node and check_sum and store in Datastore with new key
	file_encrypt_mac := append(file_encrypt, check_sum...)

	// Store in Datastore using new key
	userlib.DatastoreSet(new_ds_key, file_encrypt_mac)

	// Delete old file in Datastore
	userlib.DatastoreDelete(file_data.Datastore_key)

	// Update userdata Files[storage_key] with new file data
	userdata.Files[storage_key] = File_Data{
		new_ds_key,
		new_file_symenc_key,
		new_file_hmac_key,
		new_node_symenc_key,
		new_node_hmac_key}

	// Retrieve and decrypt every other box not associated with recipient
	// Update information and re-store in Datastore
	for i := 0; i < len(userdata.Lockboxes[storage_key]); i++ {
		box_data := userdata.Lockboxes[storage_key][i]
		if box_data.Shared_user == recipientUsername {
			box_uuid := box_data.Location
			userlib.DatastoreDelete(box_uuid)
			box_data.Shared_user = uuid.Nil.String()
		} else {
			// Retrieve and decrypt every other box
			// Update with new keys and re-encrypt
			symenc_key := box_data.Encrypt_keys[:userlib.AESBlockSizeBytes]
			hmac_key := box_data.Encrypt_keys[userlib.AESBlockSizeBytes:]

			var box Lockbox
			encrypted_box_bytes, exists := userlib.DatastoreGet(box_data.Location)
			if !exists {
				// This means the box was deleted because of a previous call to RevokeAccess
				continue
			}

			// Decrypt and verify integrity of encrypted lockbox
			length = len(encrypted_box_bytes) - 64
			ciphertext = encrypted_box_bytes[:length]
			check_sum = encrypted_box_bytes[length:]
			sum, err = userlib.HMACEval(hmac_key[:16], ciphertext)
			if err != nil {
				return errors.New("unable to generate a checksum for encrypted box")
			}

			equal = userlib.HMACEqual(check_sum, sum)
			if !equal {
				return errors.New("lockbox integrity is compromised...data is corrupted")
			}

			plaintext = userlib.SymDec(symenc_key[:16], ciphertext)
			err = json.Unmarshal(plaintext, &box)
			if err != nil {
				return errors.New("corrupted json unmarshal of lockbox")
			}

			// Re-update box with new file keys
			box.File_encrypt_key = append(new_file_symenc_key, new_file_hmac_key...)
			box.Node_encrypt_key = append(new_node_symenc_key, new_node_hmac_key...)
			box.File_location = new_ds_key

			// Re-encrypt box and store in Datastore
			box_bytes, err := json.Marshal(box)
			if err != nil {
				return errors.New("unable to Marshal lockbox")
			}

			IV := userlib.RandomBytes(userlib.AESBlockSizeBytes)
			box_encrypt := userlib.SymEnc(symenc_key[:16], IV, box_bytes)
			check_sum, err = userlib.HMACEval(hmac_key[:16], box_encrypt)
			if err != nil {
				return errors.New("unable to generate a checksum through HMACEval")
			}

			// Concatenate encrypted box and hmac
			box_encrypt_hmac := append(box_encrypt, check_sum...)
			userlib.DatastoreSet(box_data.Location, box_encrypt_hmac)
		}
	}

	// Update userdata in Datastore
	user_bytes, err := json.Marshal(userdata)
	if err != nil {
		return errors.New("cannot Marshal User struct into a JSON byte array representation")
	}

	IV = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	user_encrypt := userlib.SymEnc(userdata.SymEnc_key[:16], IV, user_bytes)
	check_sum, err = userlib.HMACEval(userdata.HMAC_key[:16], user_encrypt)
	if err != nil {
		return errors.New("unable to generate a checksum through HMACEval")
	}

	user_encrypt_hmac := append(user_encrypt, check_sum...)
	ds_key_uuid, err = uuid.FromBytes(userdata.Datastore_key)
	if err != nil {
		return errors.New("cannot convert Datastore_key byte array into a UUID")
	}

	userlib.DatastoreSet(ds_key_uuid, user_encrypt_hmac)
	return nil
}

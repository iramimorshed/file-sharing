package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const password_two = "ilovefood"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var Bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobLaptop *client.User
	var bobTablet *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// New additions: Doris and Eve
			// doris, err = client.InitUser("doris", defaultPassword)
			// Expect(err).To(BeNil())

			// // Another addition
			// eve, err = client.InitUser("eve", defaultPassword)
			// Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			// // New addition: Alice sends invite to Doris
			// userlib.DebugMsg("aliceLaptop creating invite for Doris.")
			// invite, err = aliceLaptop.CreateInvitation(aliceFile, "doris")
			// Expect(err).To(BeNil())

			// // New addition: Doris accepts invite from Alice
			// userlib.DebugMsg("Doris accepting invite from Alice under filename %s.", dorisFile)
			// err = doris.AcceptInvitation("alice", invite, dorisFile)
			// Expect(err).To(BeNil())

			// // New addition: Bob shares file with Eve
			// userlib.DebugMsg("Bob creating invite for Eve.")
			// invite, err = bob.CreateInvitation(bobFile, "eve")
			// Expect(err).To(BeNil())

			// // New addition: Eve accepts invite from Boba
			// userlib.DebugMsg("Eve accepting invite from Bob under filename %s.", eveFile)
			// err = eve.AcceptInvitation("bob", invite, eveFile)
			// Expect(err).To(BeNil())

			// // New addition: Eve appends to the file
			// userlib.DebugMsg("Eve appending to file %s, content: %s", eveFile, contentTwo)
			// err = eve.AppendToFile(eveFile, []byte(contentTwo))
			// Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {

			/*
				New additions: Alice shares with Bob and Doris.
				Bob shares with Charles.
				Alice revokes access from Bob which should also
				revoke access from Charles.
				Check to see if Doris can still make changes to file.
			*/
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			// New addition: Doris
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			// Alice invites Doris to file
			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			// Doris accepts file invite
			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			// Check that Doris can still load the file
			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			// Check that Doris can still append to the file
			userlib.DebugMsg("Checking that Doris can append to the file.")
			err = doris.AppendToFile(dorisFile, []byte("hello world"))

			// Check that Alice can load the file
			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + "hello world")))

			// Check that Doris can load the file
			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + "hello world")))

		})

	})

	Describe("Username and Password Tests", func() {
		Specify("[3.1.1] Usernames are case sensitive", func() {
			userlib.DebugMsg("Initializing user Bob")
			Bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = Bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("[3.1.1/3.1.2] Usernames are unique but passwords aren't", func() {
			userlib.DebugMsg("Initializing user Bob")
			Bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing another user Bob")
			_, err = client.InitUser("Bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("[3.1.1] Long usernames", func() {
			long_username := string(userlib.RandomBytes(10000))
			userlib.DebugMsg("Initializing user long")
			_, err = client.InitUser(long_username, defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("[3.1.1] Do not support zero-length usernames", func() {
			userlib.DebugMsg("Initializing user long")
			_, err = client.InitUser("", defaultPassword)
			userlib.DebugMsg("Error message: %s", err)
			Expect(err).ToNot(BeNil())
		})

		Specify("[3.1.2] Support zero-length password", func() {
			userlib.DebugMsg("Initializing user bob")
			bob, err = client.InitUser("bob", "")
			Expect(err).To(BeNil())
		})
	})

	Describe("User Sessions", func() {
		Specify("[3.2.1] Allow different users to run client system", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Doris")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "My name is Bob the Builder")
			err = bob.StoreFile(bobFile, []byte("My name is Bob the Builder"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "Go bears!")
			err = doris.StoreFile(dorisFile, []byte("Go bears!"))
			Expect(err).To(BeNil())
		})

		Specify("[3.2.2] The client MUST support a single user having multiple active sessions at the same time", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// Run three different sessions for a single user
			userlib.DebugMsg("Alice wants to run client on laptop.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to run client on desktop.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to run client on phone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		})

		Specify("[3.2.2] Another user sessions test", func() {
			userlib.DebugMsg("Initializing user Bob on laptop")
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob wants to start session on tablet.")
			bobTablet, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bobLaptop.StoreFile("file1.txt", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob wants to downoad file1.txt onto his tablet.")
			data, err := bobTablet.LoadFile("file1.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = bobTablet.AppendToFile("file1.txt", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob wants to downoad file1.txt onto his laptop.")
			data, err = bobLaptop.LoadFile("file1.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentThree)
			err = alice.StoreFile("file1.txt", []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice inviting Bob to share file1.txt.")
			invite, err := alice.CreateInvitation("file1.txt", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite from Alice and calles file: %s.", "file2.txt")
			err = bobLaptop.AcceptInvitation("alice", invite, "file2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob wants to download file2.txt onto his tablet.")
			data, err = bobTablet.LoadFile("file2.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
		})
	})

	Describe("Cryptography and Keys", func() {
		Specify("[3.3.2] Cannot have keys scale by files", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to run client system on phone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// A user can store multiple keys in Keystore
			length := len(userlib.KeystoreGetMap())
			Expect(length > 1).To(BeTrue())

			// Number of keys should not scale with files
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice.StoreFile("file1.txt", []byte(contentTwo))
			Expect(err).To(BeNil())

			length_by_scale := len(userlib.KeystoreGetMap()) * 2
			Expect(len(userlib.KeystoreGetMap()) == length_by_scale).To(BeFalse())
		})
	})

	Describe("Files", func() {
		Specify("[3.5.6] Filenames MAY be any length, including zero (empty string).", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to run client system on phone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			file_content := userlib.RandomBytes(500)
			userlib.DebugMsg("Storing file data")
			err = alice.StoreFile("", []byte(file_content))
			Expect(err).To(BeNil())

			file_name := string(userlib.RandomBytes(10000))
			userlib.DebugMsg("Storing file data")
			err = alicePhone.StoreFile(file_name, []byte(file_content))
			Expect(err).To(BeNil())

			// userlib.DebugMsg("Datastore Map: %v", userlib.DatastoreGetMap())

		})

		Specify("Tamper with User", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to run client system on phone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			file_content := userlib.RandomBytes(500)
			userlib.DebugMsg("Storing file data")
			err = alice.StoreFile("", []byte(file_content))
			Expect(err).To(BeNil())

			file_name := string(userlib.RandomBytes(10000))
			userlib.DebugMsg("Storing file data")
			err = alicePhone.StoreFile(file_name, []byte(file_content))
			Expect(err).To(BeNil())

			// alice_ds_key, _ := uuid.FromBytes(alice.Datastore_key)
			// user_bytes, _ := userlib.DatastoreGet(alice_ds_key)
			// random_bytes := append(user_bytes, userlib.RandomBytes(20)...)
			// userlib.DatastoreSet(alice_ds_key, random_bytes)

			// userlib.DebugMsg("Alice wants to run client system on laptop.")
			// _, err = client.GetUser("alice", defaultPassword)
			// userlib.DebugMsg("Error message: %s", err)
			// Expect(err).ToNot(BeNil())
		})

		Specify("Tamper with File Content", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to run client system on phone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			file_content := userlib.RandomBytes(500)
			userlib.DebugMsg("Storing file data")
			err = alice.StoreFile(aliceFile, []byte(file_content))
			Expect(err).To(BeNil())

			file_name := "file1.txt"
			userlib.DebugMsg("Storing file data")
			err = alicePhone.StoreFile(file_name, []byte(contentOne))
			Expect(err).To(BeNil())

			// storage_key, _ := uuid.FromBytes(userlib.Hash([]byte(file_name + "alice"))[:16])
			// key := alice.Files[storage_key].Datastore_key

			// // _, err := userlib.DatastoreGetMap()[key]
			// userlib.DatastoreSet(key, userlib.RandomBytes(200))

			// userlib.DebugMsg("Checking that alice sees expected file data.")
			// data, err := alice.LoadFile(file_name)
			// userlib.DebugMsg("Error message: %v", err)
			// Expect(err).To(BeNil())
			// Expect(data).To(Equal([]byte(contentOne)))
		})
	})

	Describe("Sharing/Revocation/Files", func() {
		Specify("Authorization of Files", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles")
			charles, err = client.InitUser("charles", password_two)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sends invite to Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite from Alice under name: %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check Bob can load the file after accepting the invitation")
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Verify Charles unable to load aliceFile")
			_, err = charles.LoadFile(aliceFile)
			userlib.DebugMsg("Error message: %s", err)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles does not have charlesFile in namespace")
			_, err = charles.LoadFile(charlesFile)
			userlib.DebugMsg("Error message: %s", err)
			Expect(err).ToNot(BeNil())
		})

		Specify("Users can have same filename in their personal namespaces", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles")
			charles, err = client.InitUser("charles", password_two)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = charles.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("Overwrite files", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice starting session from her laptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne+contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentOne+contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to download aliceFile before overwriting")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice wants to download aliceFile after overwriting")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

		})

		Specify("Revoke after sharing file with multiple users", func() {
			userlib.DebugMsg("Initializing Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Doris")
			doris, err = client.InitUser("doris", password_two)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Eve")
			eve, err = client.InitUser("eve", password_two)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Frank")
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Grace")
			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// Sending and accepting invites
			userlib.DebugMsg("Alice sends invite to Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sends invite to Charles")
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepts invite from Alice under filename %s.", charlesFile)
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob sends invite to Doris")
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepts invite from Bob as names it %s.", dorisFile)
			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob sends invite to Eve")
			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepts invite from Bob as names it %s.", eveFile)
			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris sends invite to Frank")
			invite, err = doris.CreateInvitation(dorisFile, "frank")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Frank accepts invite and names it %s.", frankFile)
			err = frank.AcceptInvitation("doris", invite, frankFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles sends invite to Grace")
			invite, err = charles.CreateInvitation(charlesFile, "grace")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Grace accepts invite and names it %s.", graceFile)
			err = grace.AcceptInvitation("charles", invite, graceFile)
			Expect(err).To(BeNil())

			// Grace overwrites file, check that other users can see the changes
			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = grace.StoreFile(graceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice sees overwritten content.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Checking that Doris sees overwritten content.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Frank appending file data: %s", contentThree)
			err = frank.AppendToFile(frankFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can see appended content.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			userlib.DebugMsg("Alice revoking Charles' access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect that Charles cannot load file.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect that Grace cannot load file.")
			_, err = grace.LoadFile(graceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect that Bob can load file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			userlib.DebugMsg("Expect that Doris can load file.")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			userlib.DebugMsg("Expect that Eve can load file.")
			_, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			userlib.DebugMsg("Expect that Frank can load file.")
			_, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree)))

			userlib.DebugMsg("Eve appending file data: %s", contentThree)
			err = eve.AppendToFile(eveFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect that Bob can load file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo + contentThree + contentThree)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect that Bob cannot append file data: %s", contentThree)
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect that Bob cannot load file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect that Doris cannot load file.")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect that Eve cannot load file.")
			_, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect that Frank cannot load file.")
			_, err = frank.LoadFile(frankFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Longer Revoke Access Test", func() {
			userlib.DebugMsg("Initialize session on alice's laptop and her phone")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Charles")
			charles, err = client.InitUser("charles", password_two)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Doris")
			doris, err = client.InitUser("doris", password_two)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Eve")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Frank")
			frank, err = client.InitUser("frank", password_two)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing Grace")
			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			// userlib.DebugMsg("Initializing Horace")
			// horace, err = client.InitUser("horace", defaultPassword)
			// Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file,%s, with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sends invite to Bob using her phone")
			invite, err := alicePhone.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite from Alice and names file: %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sends invite to Bob using her laptop")
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepts invite from Alice and names file: %s", charlesFile)
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob sends invite to Doris")
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepts invite from Bob and names file: %s", dorisFile)
			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles sends invite to Eve")
			invite, err = charles.CreateInvitation(charlesFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepts invite from Charles and names file: %s", eveFile)
			err = eve.AcceptInvitation("charles", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Alice can load file from her phone.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Expect Bob can load file")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Expect Doris can load file")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Expect Charles can load file")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Expect Eve can load file")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Charles appends to file %s with content: %s", charlesFile, contentTwo)
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Alice can load the file")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Expect Bob can load file")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Expect Doris can load file")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Expect Charles can load file")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Expect Eve can load file")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Doris appends to file %s with content: %s", dorisFile, contentThree)
			err = doris.AppendToFile(dorisFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Alice can load file")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Expect Bob can load file")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Expect Doris can load file")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Expect Charles can load file")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Expect Eve can load file")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Alice appends to file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Alice can load file")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			userlib.DebugMsg("Expect Bob can load file")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			userlib.DebugMsg("Expect Doris can load file")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			userlib.DebugMsg("Expect Charles can load file")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			userlib.DebugMsg("Expect Eve can load file")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access")
			err = alicePhone.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Bob cannot load file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect Bob cannot append to file")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect Bob cannot store or ovewrite file")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob cannot create invite")
			_, err = bob.CreateInvitation(bobFile, "frank")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect Doris cannot load file")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect Doris cannot append file")
			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect Doris cannot store or overwrite file")
			err = doris.StoreFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect Doris cannot invite others to file")
			_, err = doris.CreateInvitation(dorisFile, "frank")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Expect Alice can load file")
			_, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Alice can append to file")
			err = alicePhone.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Alice can overwrite file")
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Expect Alice can invite someone to file")
			invite, err = alice.CreateInvitation(aliceFile, "frank")
			Expect(err).To(BeNil())
		})

	})

})

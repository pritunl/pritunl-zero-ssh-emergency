package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/dropbox/godropbox/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/mgo.v2/bson"
	"hash/fnv"
	"io/ioutil"
	"strings"
	"syscall"
	"time"
)

type ReadError struct {
	errors.DropboxError
}

type WriteError struct {
	errors.DropboxError
}

type ParseError struct {
	errors.DropboxError
}

type importData struct {
	Keys []string `json:"keys"`
}

func ParsePemKey(pass string, data string) (key crypto.PrivateKey, err error) {
	encBlock, _ := pem.Decode([]byte(data))

	blockBytes, err := x509.DecryptPEMBlock(encBlock, []byte(pass))
	if err != nil {
		err = &ParseError{
			errors.Wrap(err, "main: Failed to decrypt key"),
		}
		return
	}

	switch encBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(blockBytes)
		if err != nil {
			err = &ParseError{
				errors.Wrap(err, "main: Failed to parse rsa key"),
			}
			return
		}
		break
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(blockBytes)
		if err != nil {
			err = &ParseError{
				errors.Wrap(err, "main: Failed to parse ec key"),
			}
			return
		}
		break
	default:
		err = &ParseError{
			errors.Newf("main: Unknown key type '%s'", encBlock.Type),
		}
		return
	}

	return
}

func MarshalCertificate(cert *ssh.Certificate, comment string) []byte {
	b := &bytes.Buffer{}
	b.WriteString(cert.Type())
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(cert.Marshal())
	e.Close()
	b.WriteByte(' ')
	b.Write([]byte(comment))
	return b.Bytes()
}

func CreateCertificate(pass string, privKey string, sshPubKey string,
	roles []string) (certMarshaled string, err error) {

	privateKey, err := ParsePemKey(pass, privKey)
	if err != nil {
		return
	}

	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPubKey))
	if err != nil {
		err = &ParseError{
			errors.Wrap(err, "authority: Failed to parse ssh public key"),
		}
		return
	}

	serialHash := fnv.New64a()
	serialHash.Write([]byte(bson.NewObjectId().Hex()))
	serial := serialHash.Sum64()

	validAfter := time.Now().Add(-5 * time.Minute).Unix()
	validBefore := time.Now().Add(30 * time.Minute).Unix()

	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           "emergency",
		ValidPrincipals: roles,
		ValidAfter:      uint64(validAfter),
		ValidBefore:     uint64(validBefore),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return
	}

	certMarshaled = string(MarshalCertificate(cert, comment))

	return
}

func Certificate() (err error) {
	importPath := flag.Arg(0)
	sshPubPath := flag.Arg(1)

	if importPath == "" {
		err = &ReadError{
			errors.Wrap(err, "main: Missing import path"),
		}
		return
	}

	if sshPubPath == "" {
		err = &ReadError{
			errors.Wrap(err, "main: Missing SSH public key path"),
		}
		return
	}

	roles := []string{}
	args := flag.Args()
	for _, arg := range args[2:] {
		roles = append(roles, arg)
	}

	if len(roles) == 0 {
		roles = []string{"emergency"}
	}

	fmt.Print("Enter encryption passphrase: ")
	passByt, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		err = &ReadError{
			errors.Wrap(err, "main: Failed to read passphrase"),
		}
		return
	}
	pass := string(passByt)
	fmt.Println("")

	marhData, err := ioutil.ReadFile(importPath)
	if err != nil {
		err = &ReadError{
			errors.Wrap(err, "main: Failed to read import file"),
		}
		return
	}

	sshPubKeyByt, err := ioutil.ReadFile(sshPubPath)
	if err != nil {
		err = &ReadError{
			errors.Wrap(err, "main: Failed to read import file"),
		}
		return
	}
	sshPubKey := string(sshPubKeyByt)

	data := &importData{}

	err = json.Unmarshal(marhData, data)
	if err != nil {
		err = &ParseError{
			errors.Wrap(err, "main: Failed to parse import file"),
		}
		return
	}

	certs := []string{}
	for _, key := range data.Keys {
		cert, e := CreateCertificate(
			pass,
			key,
			sshPubKey,
			roles,
		)
		if e != nil {
			err = e
			return
		}

		certs = append(certs, cert)
	}
	certsStr := strings.Join(certs, "\n")

	sshCertPath := strings.Replace(sshPubPath, ".pub", "-cert.pub", 1)

	err = ioutil.WriteFile(sshCertPath, []byte(certsStr), 0644)
	if err != nil {
		err = &WriteError{
			errors.Wrapf(err,
				"main: Failed to write ssh certificate at %s", sshCertPath),
		}
		return
	}

	fmt.Printf("Wrote SSH certificate to %s\n", sshCertPath)

	return
}

func main() {
	flag.Parse()

	err := Certificate()
	if err != nil {
		panic(err)
	}
}

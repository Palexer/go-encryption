package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func printErrExit(a ...interface{}) {
	fmt.Fprintf(os.Stderr, "encrypt: ")
	fmt.Fprint(os.Stderr, a...)
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}

func createHash(key string) []byte {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

func encrypt(key, content []byte) []byte {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		printErrExit("failed to create cipher: ", err)
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		printErrExit("failed to create gcm: ", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		printErrExit(err)
	}
	return gcm.Seal(nonce, nonce, content, nil)
}

func decrypt(key, content []byte) []byte {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		printErrExit(err)
	}

	gcmDecrypt, err := cipher.NewGCM(cphr)
	if err != nil {
		printErrExit(err)
	}

	nonceSize := gcmDecrypt.NonceSize()
	if len(content) < nonceSize {
		printErrExit(err)
	}

	nonce, encryptedMessage := content[:nonceSize], content[nonceSize:]
	plaintext, err := gcmDecrypt.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		printErrExit(err)
	}
	return plaintext
}

func main() {
	passwordFlag := flag.String("p", "", "a passphrase to encrypt/decrypt the given files")
	overwrite := flag.Bool("w", false, "overwrite the original file with the encrypted file")
	enc := flag.Bool("e", false, "encrypt the given files")
	dec := flag.Bool("d", false, "decrypt the given files")
	output := flag.String("o", "", "specify an output file path (only works with one file)")
	flag.Parse()

	if len(flag.Args()) < 1 {
		printErrExit("no files specified")
	}

	if *enc == *dec {
		printErrExit("you can't use encryption and decryption at the same time")
	}

	hashKey := createHash(*passwordFlag)

	if *enc {
		for _, file := range flag.Args() {
			originalContent, err := os.ReadFile(file)
			if err != nil {
				printErrExit("failed to read file: ", err)
			}

			if *overwrite {
				var newFilepath string
				if len(flag.Args()) == 1 && *output != "" {
					newFilepath = *output
				} else {
					newFilepath = file
				}

				err = os.WriteFile(newFilepath, encrypt(hashKey, originalContent), fs.ModePerm)
				if err != nil {
					printErrExit("failed to write encrypted file: ", err)
				}
			} else {
				var newFilepath string
				if len(flag.Args()) == 1 && *output != "" {
					newFilepath = *output
				} else {
					newFilepath = strings.TrimSuffix(file, filepath.Ext(file)) + "-enc" + filepath.Ext(file)
				}
				err = os.WriteFile(newFilepath, encrypt(hashKey, originalContent), fs.ModePerm)
				if err != nil {
					printErrExit("failed to write encrypted file: ", err)
				}
			}
		}
	} else {
		for _, file := range flag.Args() {
			originalContent, err := os.ReadFile(file)
			if err != nil {
				printErrExit("failed to read file: ", err)
			}

			if *overwrite {
				var newFilepath string
				if len(flag.Args()) == 1 && *output != "" {
					newFilepath = *output
				} else {
					newFilepath = file
				}

				err = os.WriteFile(newFilepath, decrypt(hashKey, originalContent), fs.ModePerm)
				if err != nil {
					printErrExit("failed to write decrypted file: ", err)
				}
			} else {
				var newFilepath string
				if len(flag.Args()) == 1 && *output != "" {
					newFilepath = *output
				} else {
					newFilepath = strings.TrimSuffix(file, filepath.Ext(file)) + "-dec" + filepath.Ext(file)
				}

				err = os.WriteFile(newFilepath, decrypt(hashKey, originalContent), fs.ModePerm)
				if err != nil {
					printErrExit("failed to write decrypted file: ", err)
				}
			}
		}
	}
}

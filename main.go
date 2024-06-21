package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

func main() {
	password := "mypassword123"
	key := "myverystrongpasswordo32bitlength"

	encrypted, err := encrypt(password, key)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}

	fmt.Println("Encryped: ", encrypted)

	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}

	fmt.Println("Decrypted: ", decrypted)

}

func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func encrypt(plaintext, password string) (string, error) {
	key := deriveKey(password)
	plainTextBytes := []byte(plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nonce, nonce, plainTextBytes, nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decrypt(ciphertext, password string) (string, error) {
	key := deriveKey(password)
	cipherTextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, cipherText := cipherTextBytes[:nonceSize], cipherTextBytes[nonceSize:]

	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainTextBytes), nil
}

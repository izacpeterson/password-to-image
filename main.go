package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

func main() {
	hashedPasswordFile := "hashedpassword.txt"
	fileContent, err := os.ReadFile(hashedPasswordFile)

	hashedPassword := string(fileContent)

	if err != nil {
		var masterPassword string

		fmt.Print("Error opeining master password. Please set a new Master Password. This password will be used to encrypt your other passwords, so choose wisely.")
		fmt.Scanln(&masterPassword)

		hashedMasterPassword := deriveKey(masterPassword)

		file, err := os.Create("hashedpassword.txt")
		if err != nil {
			fmt.Println("Error Creating File", err)
			return

		}
		defer file.Close()

		_, err = file.WriteString(string(hashedMasterPassword))
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}

		os.Exit(0)
	}

	if len(os.Args) < 2 {
		fmt.Println("Please enter a password")
		os.Exit(0)
	}

	inputPassword := os.Args[1]

	if bytes.Equal(deriveKey(inputPassword), []byte(hashedPassword)) {
		fmt.Println("Pass Match")
	} else {
		fmt.Println("Pass no Match")
		os.Exit(0)
	}

	myPasswords := make(map[string]string)

	fmt.Println("Welcome to Password-to-Image")
	fmt.Println("What would you like to do?")
	fmt.Println("a: Add a password")
	fmt.Println("l: list your passwords")
	fmt.Println("g: get a signle password")

	var userInput string

	fmt.Print(": ")
	fmt.Scanln(&userInput)

	switch userInput {
	case "a":
		var label, password string
		fmt.Print("Label: ")
		fmt.Scanln(&label)

		fmt.Print("Password: ")
		fmt.Scanln(&password)

		myPasswords[label] = password

		encryptedPasswords := prepareText(myPasswords, hashedPassword)
		binaryPasswords := textToBinary(encryptedPasswords)
		binaryToImage(binaryPasswords)

	case "l":
		textFromImage, err := imageToText()

		if err != nil {
			fmt.Println("error: ", err)
		} else {
			decryptedText, err := decrypt(textFromImage, hashedPassword)
			if err != nil {
				fmt.Println("error: ", err)
			}
			myPasswords = textToMap(decryptedText)
		}

		fmt.Println("Your passwords:")
		for key, value := range myPasswords {
			fmt.Printf("%v: %v", key, value)
		}
		os.Exit(0)
	case "g":

	default:
		fmt.Println("You picked wrong. Goodbye.")
		os.Exit(0)
	}

}

func textToMap(s string) map[string]string {

	result := make(map[string]string)
	s = s[1 : len(s)-1]
	pairs := strings.Split(s, "][")
	for _, pair := range pairs {
		parts := strings.Split(pair, ":")
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func prepareText(passwords map[string]string, masterPassword string) string {
	var passwordString string = ""
	for key, value := range passwords {
		passwordString = passwordString + "[" + key + ":" + value + "]"
	}

	encryptedPasswordString, err := encrypt(passwordString, masterPassword)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}

	return encryptedPasswordString
}

func textToBinary(text string) string {
	var binarying string
	for _, c := range text {
		binarying += fmt.Sprintf("%08b", c)
	}
	return binarying
}

func binaryToText(binary string) string {
	var text strings.Builder

	if len(binary)%8 != 0 {
		binary = binary[:len(binary)-(len(binary)%8)]
	}

	// Split the binary string into 8-bit chunks
	for i := 0; i < len(binary); i += 8 {
		byteStr := binary[i : i+8]
		byteValue, err := strconv.ParseUint(byteStr, 2, 8)
		if err != nil {
			return ""
		}
		text.WriteByte(byte(byteValue))
	}

	return text.String()
}

func binaryToImage(binary string) {
	length := len(binary)
	imageDim := int(math.Ceil(math.Sqrt(float64(length))))

	fmt.Println("Length: ", length)
	fmt.Println("Image Dimensions: ", imageDim)

	img := image.NewRGBA(image.Rect(0, 0, imageDim, imageDim))

	var pixelIndex int

	for y := 0; y < imageDim; y++ {
		for x := 0; x < imageDim; x++ {
			if pixelIndex < length {
				if binary[pixelIndex] == '0' {
					img.Set(x, y, color.RGBA{0, 0, 0, 255})
				} else {
					img.Set(x, y, color.RGBA{255, 255, 255, 255})
				}
				pixelIndex++
			} else {
				img.Set(x, y, color.RGBA{0, 0, 0, 255}) // Padding with black if needed
			}
		}
	}

	file, err := os.Create("image.png")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Encode and save the image to the file
	if err := png.Encode(file, img); err != nil {
		panic(err)
	}
}

func imageToText() (string, error) {
	inputImage := "image.png"
	file, err := os.Open(inputImage)
	if err != nil {
		fmt.Println("ERROR OPENING IMAGE: ", err)
		return "", err
	}
	defer file.Close()

	img, err := png.Decode(file)
	if err != nil {
		fmt.Println("ERROR DECODING IMAGE: ", err)
		return "", err
	}

	var binarying string

	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixelColor := color.RGBAModel.Convert(img.At(x, y)).(color.RGBA)
			if pixelColor.R == 255 {
				binarying += "1"
			} else {
				binarying += "0"
			}
		}
	}

	result := binaryToText(binarying)

	// trim invalid runes
	validBase64Length := len(result)
	for validBase64Length > 0 && !isValidBase64Char(rune(result[validBase64Length-1])) {
		validBase64Length--
	}

	result = result[:validBase64Length]

	return result, err
}

// I was getting an error about illegal base64 runes. This should check for those. Probably a return or tab or something
func isValidBase64Char(c rune) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
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

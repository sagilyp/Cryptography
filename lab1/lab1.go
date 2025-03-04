package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/sagilyp/lab1/mycrypto"
)

func main() {
	// Валидация моей реализации CBC
	fmt.Println("<<<---CBC Validation--->>>")
	plaintext := []byte("London Bridge is Down!")
	key, err := hex.DecodeString("140b41b22a29beb4061bda66b6747e14")
	if err != nil {
		log.Fatal(err)
	}
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	iv := make([]byte, aesBlock.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}
	padded := mycrypto.Pkcs7Pad(plaintext, aesBlock.BlockSize())
	cbcEncrypter := cipher.NewCBCEncrypter(aesBlock, iv)
	enc := make([]byte, len(padded))
	cbcEncrypter.CryptBlocks(enc, padded)
	result := append(iv, enc...)
	fmt.Println("Standard CBC Encryption:", hex.EncodeToString(result))
	myCBC := &mycrypto.MyCipher{}
	if err := myCBC.SetKey(key); err != nil {
		log.Fatal(err)
	}
	if err := myCBC.SetMode(mycrypto.ModeCBC); err != nil {
		log.Fatal(err)
	}
	decr, err := myCBC.Decrypt(result, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Lab CBC Decryption of standard CBC result:", string(decr))

	// Расшифровка шифротекстов в режиме CTR и CBC
	fmt.Printf("\nCBC Decryption Test:\n")
	cbcKey, _ := hex.DecodeString("140b41b22a29beb4061bda66b6747e14")
	cbcCiphertext1, _ := hex.DecodeString("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
	cbcCiphertext2, _ := hex.DecodeString("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")
	cipherCBC := &mycrypto.MyCipher{}
	if err := cipherCBC.SetKey(cbcKey); err != nil {
		log.Fatal(err)
	}
	if err := cipherCBC.SetMode(mycrypto.ModeCBC); err != nil {
		log.Fatal(err)
	}
	fmt.Println("I'm starting to decipher it in CBC mode...")
	cbcPlaintext1, err := cipherCBC.Decrypt(cbcCiphertext1, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("CBC Decrypted:", string(cbcPlaintext1))
	cbcPlaintext2, err := cipherCBC.Decrypt(cbcCiphertext2, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("CBC Decrypted:", string(cbcPlaintext2))

	fmt.Printf("\nCTR Decryption Test:\n")
	ctrKey, _ := hex.DecodeString("36f18357be4dbd77f050515c73fcf9f2")
	ctrCiphertext1, _ := hex.DecodeString("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
	ctrCiphertext2, _ := hex.DecodeString("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")
	cipherCTR := &mycrypto.MyCipher{}
	if err := cipherCTR.SetKey(ctrKey); err != nil {
		log.Fatal(err)
	}
	if err := cipherCTR.SetMode(mycrypto.ModeCTR); err != nil {
		log.Fatal(err)
	}
	fmt.Println("I'm starting to decipher it in CTR mode...")
	ctrPlaitnext1, err := cipherCTR.Decrypt(ctrCiphertext1, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("CTR Decrypted:", string(ctrPlaitnext1))
	ctrPlaitnext2, err := cipherCTR.Decrypt(ctrCiphertext2, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("CTR Decrypted:", string(ctrPlaitnext2))

	//Шифрование и расшифрование произвольного текста (~2.5 блока) для всех режимов
	fmt.Println("\nFull Encryption/Decryption Test:")
	secretText := "Hello, my name is Satoshi Nakamoto! Do you have some BTC?"
	modes := []string{mycrypto.ModeECB, mycrypto.ModeCBC, mycrypto.ModeCFB, mycrypto.ModeOFB, mycrypto.ModeCTR}
	for _, mode := range modes {
		fmt.Printf("\n<<<--- Mode: %s --->>>\n", mode)
		mc := &mycrypto.MyCipher{}
		var key []byte
		if mode == mycrypto.ModeCTR {
			key, _ = hex.DecodeString("36f18357be4dbd77f050515c73fcf9f2")
		} else {
			key, _ = hex.DecodeString("140b41b22a29beb4061bda66b6747e14")
		}
		if err := mc.SetKey(key); err != nil {
			log.Fatal(err)
		}
		if err := mc.SetMode(mode); err != nil {
			log.Fatal(err)
		}
		cipherText, err := mc.Encrypt([]byte(secretText), nil)
		if err != nil {
			log.Printf("%s Encryption error: %v\n", mode, err)
			continue
		}
		plainText, err := mc.Decrypt(cipherText, nil)
		if err != nil {
			log.Printf("%s Decryption error: %v\n", mode, err)
			continue
		}
		fmt.Printf("Original: %s\n", secretText)
		fmt.Printf("Decrypted: %s\n", plainText)
	}
}

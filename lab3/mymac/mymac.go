package mymac

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

// --- Константы ---
const (
	AESBlockSize = 16
	AESKeySize   = 16
	SHABlockSize = 32
	OMACTagSize  = 16
	TruncTagSize = 8
	HMACTagSize  = 16

	Rn = 0x87
)

const (
	OMAC      = "OMAC"
	HMAC      = "HMAC"
	TRUNCATED = "TRUNCATED"
)

// MyMAC - структура для вычисления подписи с потоковым интерфейсом
type MyMAC struct {
	key      []byte
	k1, k2   []byte
	state    []byte
	mode     string
	aesBlock cipher.Block
	hmacHash hash.Hash
}

// SetMode задает алгоритм вычисления подписи
func (mm *MyMAC) SetMode(newmode string) error {
	switch newmode {
	case TRUNCATED, HMAC, OMAC:
		mm.mode = newmode
		return nil
	default:
		return fmt.Errorf("wrong mode [%s] detected", newmode)
	}
}

// SetKey устанавливает ключ шифрования/расшифрования и инициализирует AES‑блочный шифр
func (mm *MyMAC) SetKey(newkey []byte) error {
	var err error
	switch mm.mode {
	case OMAC, TRUNCATED:
		if len(newkey) != AESKeySize {
			return fmt.Errorf("invalid key length: got %d, expected %d", len(newkey), AESKeySize)
		}
		mm.key = newkey
		mm.aesBlock, err = aes.NewCipher(newkey)
		if err != nil {
			return err
		}
		err = mm.generateSubkeys()
		if err != nil {
			return err
		}
	case HMAC:
		mm.hmacHash = sha256.New()
		if len(newkey) != SHABlockSize {
			hash := sha256.Sum256(newkey)
			newkey = hash[:]
		}
		mm.key = newkey
		err = mm.generateSubkeys()
		if err != nil {
			return err
		}
		mm.hmacHash.Write(mm.k1)
	default:
		return fmt.Errorf("undefined algorithm %s", mm.mode)
	}
	return nil
}

// BlockCipherEncrypt выполняет одноблочное шифрование с помощью AES
func (mm *MyMAC) AesBlockEncrypt(data []byte) ([]byte, error) {
	if len(data) != AESBlockSize {
		return nil, fmt.Errorf("AESBlockEncrypt: data length must be %d", AESBlockSize)
	}
	out := make([]byte, AESBlockSize)
	mm.aesBlock.Encrypt(out, data)
	return out, nil
}

// MacAddBlock обновляет внутреннее состояние MAC для блока данных
func (mm *MyMAC) MacAddBlock(dataBlock []byte) error {
	if len(dataBlock) != AESBlockSize {
		return fmt.Errorf("MacAddBlock: data length must be %d", AESBlockSize)
	}
	switch mm.mode {
	case OMAC, TRUNCATED:
		var prevState []byte
		if len(mm.state) == AESBlockSize {
			prevState = mm.state
		} else {
			prevState = make([]byte, AESBlockSize)
			mm.state = make([]byte, AESBlockSize)
		}
		xored, err := xorBytes(prevState, dataBlock)
		if err != nil {
			return err
		}
		newState, err := mm.AesBlockEncrypt(xored)
		if err != nil {
			return err
		}
		mm.state = newState
	case HMAC:
		var err error
		if len(mm.state) != AESBlockSize && mm.k1 != nil {
			_, err = mm.hmacHash.Write(mm.k1)
			if err != nil {
				return err
			}
			mm.state = make([]byte, AESBlockSize)
		}
		_, err = mm.hmacHash.Write(dataBlock)
		if err != nil {
			return err
		}
		mm.state = dataBlock
	default:
		return fmt.Errorf("undefined algorithm %s", mm.mode)
	}
	return nil
}

// MacFinalize завершает вычисление MAC и возвращает тег
func (mm *MyMAC) MacFinalize(lastBlock []byte) ([]byte, error) {
	var err error
	switch mm.mode {
	case OMAC:
		// если последний блок полон, то используем k1, иначе – k2
		var xored []byte
		if len(lastBlock) == AESBlockSize {
			xored, err = xorBytes(lastBlock, mm.state)
			if err != nil {
				return nil, err
			}
			xored, err = xorBytes(xored, mm.k1)
			if err != nil {
				return nil, err
			}
		} else {
			padded := pad(lastBlock, AESBlockSize)
			xored, err = xorBytes(padded, mm.state)
			if err != nil {
				return nil, err
			}
			xored, err = xorBytes(xored, mm.k2)
			if err != nil {
				return nil, err
			}
		}
		tag, err := mm.AesBlockEncrypt(xored)
		if err != nil {
			return nil, err
		}
		return tag[:OMACTagSize], nil
	case TRUNCATED:
		var xored []byte
		if len(lastBlock) == AESBlockSize {
			xored, err = xorBytes(lastBlock, mm.state)
			if err != nil {
				return nil, err
			}
			xored, err = xorBytes(xored, mm.k1)
			if err != nil {
				return nil, err
			}
		} else {
			padded := Pkcs7Pad(lastBlock, AESBlockSize)
			xored, err = xorBytes(padded, mm.state)
			if err != nil {
				return nil, err
			}
			xored, err = xorBytes(xored, mm.k2)
			if err != nil {
				return nil, err
			}
		}
		tag, err := mm.AesBlockEncrypt(xored)
		if err != nil {
			return nil, err
		}
		return tag[:TruncTagSize], nil
	case HMAC:
		mm.MacAddBlock(lastBlock)
		innerHash := mm.hmacHash.Sum(nil)                       // H(k1 || message)
		outerHash := sha256.Sum256(append(mm.k2, innerHash...)) // H(k2 || H(k1 || message))
		return outerHash[:HMACTagSize], nil
	default:
		return nil, fmt.Errorf("undefined algorithm %s", mm.mode)
	}
}

// ComputeMac вычисляет MAC для данных за один вызов, используя MacAddBlock и MacFinalize
func (mm *MyMAC) ComputeMac(message []byte) ([]byte, error) {
	if mm.mode != HMAC && mm.mode != OMAC && mm.mode != TRUNCATED {
		return nil, fmt.Errorf("undefined algorithm %s", mm.mode)
	}
	mm.state = nil // сброс состояний
	if mm.mode == HMAC {
		mm.hmacHash.Reset() // чистим от мусора
	}
	for len(message) > AESBlockSize {
		block := message[:AESBlockSize]
		if err := mm.MacAddBlock(block); err != nil {
			return nil, err
		}
		message = message[AESBlockSize:]
	}
	return mm.MacFinalize(message)
}

// VerifyMac вычисляет MAC для данных и сравнивает его с переданным тегом
func (mm *MyMAC) VerifyMac(message, tag []byte) (bool, error) {
	mm.state = make([]byte, AESBlockSize) // сбрасываем внутреннее состояние перед проверкой
	computed, err := mm.ComputeMac(message)
	if err != nil {
		return false, err
	}
	return MacEqual(computed, tag), nil
}

// generateSubkeys вычисляет ключи k1 и k2
func (mm *MyMAC) generateSubkeys() error {
	var K1, K2 []byte
	switch mm.mode {
	case OMAC, TRUNCATED:
		zero := make([]byte, AESBlockSize)
		L, err := mm.AesBlockEncrypt(zero)
		if err != nil {
			return err
		}
		K1 = leftShift(L)
		if L[0]&0x80 != 0 { // L & 10000000
			for i := range K1 {
				K1[i] ^= Rn
			}
		}
		K2 = leftShift(K1)
		if K1[0]&0x80 != 0 {
			for i := range K2 {
				K2[i] ^= Rn
			}
		}
	case HMAC:
		K1 = make([]byte, SHABlockSize)
		K2 = make([]byte, SHABlockSize)
		for i := range K1 {
			K1[i] = mm.key[i] ^ 0x36
			K2[i] = mm.key[i] ^ 0x5c
		}
	default:
		return fmt.Errorf("undefined algorithm %s", mm.mode)
	}
	mm.k1, mm.k2 = K1, K2
	return nil
}

// leftShift выполняет побитовый сдвиг влево для массива байтов
func leftShift(input []byte) []byte {
	out := make([]byte, len(input))
	carry := byte(0)
	for i := len(input) - 1; i >= 0; i-- {
		out[i] = (input[i] << 1) | carry
		carry = (input[i] & 0x80) >> 7
	}
	return out
}

// добавляет обычный паддинг 100...0 к данным
func pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		return data // Уже выровнено, паддинг не нужен
	}
	padding := make([]byte, padLen)
	padding[0] = 0x80 // 10000000
	return append(data, padding...)
}

// pkcs7Pad добавляет PKCS7-паддинг к данным
func Pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// xorBytes выполняет операцию XOR двух срезов байтов одинаковой длины
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("xor: slices must have equal length")
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res, nil
}

// hmacEqual сравнивает два тега в константное время
func MacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := range a {
		result |= int(a[i] ^ b[i])
	}
	return result == 0
}

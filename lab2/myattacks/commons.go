package myattacks

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

const (
	MinOut             = 8
	MaxOut             = 24
	MsgLen             = 6
	DistBits           = 2
	NumWorkers         = 4
	NumCollisionNeeded = 150
)

// Структура для хранения пары сообщений, давшей одинаковый хэш
type Collision struct {
	X string
	Y string
}

// звено для хранения информации о состоянии цепочки
type Chain struct {
	seed  string
	val   string
	steps int
	WID   int
}

// Усечённая хэш-функция
// вычисляет SHA-256 от msg и возвращает последние outbits бит в виде строки из "0" и "1"
func SHA_xx(msg []byte, outbits int) (string, error) {
	if outbits < MinOut || outbits > MaxOut {
		return "", errors.New("Invalid out vector size")
	}
	hash := sha256.Sum256(msg)
	hashInt := new(big.Int).SetBytes(hash[:])

	mask := new(big.Int).Lsh(big.NewInt(1), uint(outbits))
	mask.Sub(mask, big.NewInt(1)) // == 00...0111.111
	result := new(big.Int).And(hashInt, mask)
	return fmt.Sprintf("%0*b", outbits, result), nil
}

// проверяет, встречалась ли такая коллизия ранее
func containColl(arr []Collision, data Collision) bool {
	for _, val := range arr {
		if val.X == data.X && val.Y == data.Y || val.X == data.Y && val.Y == data.X {
			return true
		}
	}
	return false
}

// перевод двоичной строки в хекс-значение
func BinToHex(binStr string) (string, error) {
	n, ok := new(big.Int).SetString(binStr, 2)
	if !ok {
		return "", errors.New("invalid binary string")
	}
	return fmt.Sprintf("%x", n), nil
}

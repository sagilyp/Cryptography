package myattacks

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

// Атака на основе парадокса о днях рождения
func BirthdayAttack(num int, outBits int) ([]Collision, int, int, time.Duration, error) {
	collisions := []Collision{}
	dict := make(map[string]string)
	iterations := 0
	start := time.Now()
	v := make([]byte, MsgLen)
	for len(collisions) < num {
		if n, err := rand.Read(v); err != nil || n != MsgLen {
			return nil, iterations, 0, time.Since(start), errors.New("failed to generate random vector")
		}
		h, err := SHA_xx(v, outBits)
		if err != nil {
			return nil, iterations, 0, time.Since(start), err
		}
		if prev, ok := dict[h]; ok {
			if prev != hex.EncodeToString(v) && !containColl(collisions, Collision{X: prev, Y: hex.EncodeToString(v)}) {
				collisions = append(collisions, Collision{X: prev, Y: hex.EncodeToString(v)})
			}
		} else {
			dict[h] = hex.EncodeToString(v)
		}
		iterations++
	}
	passed := time.Since(start)
	mem := len(dict)*outBits + int(unsafe.Sizeof(v))*8
	fmt.Printf("Birthday Attack(%d-bit): Found %d collisions after %d iterations (%s elapsed).\n",
		outBits, len(collisions), iterations, passed)
	return collisions, iterations, mem, passed, nil
}

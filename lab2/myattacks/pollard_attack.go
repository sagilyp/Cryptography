package myattacks

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
	"unsafe"
)

// randomState генерирует случайное состояние в виде двоичной строки длины outBits.
func randomState(outBits int) (string, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(outBits))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*b", outBits, n), nil
}

// проверяет, является ли значение отличительным
func isDistinguished(s string, distinguishedBits int) bool {
	if len(s) < distinguishedBits {
		return false
	}
	for i := 0; i < distinguishedBits; i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// инъективная функция (конкатенация четырёх нулей в конец)
func P(x string) string {
	return x + "0000"
}

// Функция для преобразования двоичной строки в байтовый срез
func binToBytes(binStr string) ([]byte, error) {
	for _, c := range binStr {
		if c != '0' && c != '1' {
			return nil, errors.New("binary string contains invalid characters")
		}
	}
	hexStr, _ := BinToHex(binStr)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	return hex.DecodeString(hexStr)
}

func chainFunc(x string, outBits int) (string, error) {
	xb, _ := binToBytes(x)
	hash, err := SHA_xx(xb, outBits)
	if err != nil {
		return "", err
	}
	appended := P(hash)
	if len(appended) < outBits {
		return "", errors.New("chainFunc: result length too short")
	}
	return appended, nil
}

// Для двух цепочек, у которых найдено одно и то же отличительное значение,
// применяем разность d = i - j к цепочке с большим номером, затем итеративно идём синхронно,
// пока не найдём точное совпадение.
func findExactCollision(seedA, seedB string, delta int, outBits int) (Collision, error) {
	// предполагаем, что цепочка А длиннее цепочки В
	var valA, valB string
	var err error
	valA = seedA
	valB = seedB
	for i := 0; i < delta; i++ {
		valA, err = chainFunc(valA, outBits)
		if err != nil {
			return Collision{}, err
		}
	}
	var collision Collision
	for i := 0; i < 10e6; i++ {
		collision = Collision{X: valA, Y: valB}
		valA, err = chainFunc(valA, outBits)
		valB, err = chainFunc(valB, outBits)
		if err != nil {
			return Collision{}, err
		}
		if valA == valB {
			return collision, nil
		}
	}
	return Collision{}, errors.New("exact collision not found")
}

// симуляция параллельной атаки Полларда
func PollardAttack(outBits int, distinguishedBits int, numColls int, numWorkers int) ([]Collision, int, int, time.Duration, error) {
	chains := make([]Chain, numWorkers)
	dists := make(map[string]Chain)
	collisions := []Collision{}
	iterations := 0
	start := time.Now()
	successTime := time.Duration(0)
	// анонимная функция обнуления цепочек
	reset := func(chains []Chain, id int, outBits int) error {
		seed, err := randomState(outBits)
		if err != nil {
			return err
		}
		chains[id] = Chain{seed: seed, val: seed, steps: 0, WID: id}
		return nil
	}
	// Инициализируем цепочки
	for i := 0; i < numWorkers; i++ {
		err := reset(chains, i, outBits)
		if err != nil {
			return nil, iterations, 0, time.Since(start), err
		}
	}
	// обновляем все цепочки
	for len(collisions) < numColls {
		// если крутимся очнь долго, то всё забываем
		if iterations >= 10e4 {
			for i := 0; i < numWorkers; i++ {
				err := reset(chains, i, outBits)
				if err != nil {
					return nil, iterations, 0, time.Since(start), err
				}
			}
			for key := range dists { // удаляем значительную точку
				delete(dists, key)
			}
			iterations = 0
			continue
		}
		iterations++
		for i := 0; i < numWorkers; i++ {
			next, err := chainFunc(chains[i].val, outBits)
			if err != nil {
				continue
			}
			chains[i].steps++
			chains[i].val = next
			if isDistinguished(chains[i].val, distinguishedBits) {
				if val, exists := dists[chains[i].val]; exists { // если уже была такая отличительная точка
					// Здесь фиксируем коллизию – независимо от того, совпадают ли seed или нет,
					// поскольку по заданию коллизия может быть найдена даже внутри одной цепочки.
					var longerChain, shorterChain Chain
					if val.steps >= chains[i].steps {
						longerChain, shorterChain = val, chains[i]
					} else {
						longerChain, shorterChain = chains[i], val
					}
					delta := longerChain.steps - shorterChain.steps
					collisionStart := time.Now()
					collision, err := findExactCollision(longerChain.seed, shorterChain.seed, delta, outBits)
					if err != nil {
						return nil, iterations, 0, time.Since(start), err
					}
					if !containColl(collisions, collision) { // если такой коллизии раньше не встречалось, то записываем в словарь
						collisions = append(collisions, collision)
						successTime += time.Since(collisionStart)
					}
					// Если нашли, но она уже есть - все эти данные просто выкидываем, считаем запуск плохим и делаем вид, что его и не было никогда.
					// заново инициализируем цепочки
					for key, chain := range dists { // удаляем значительную точку
						if chain.seed == longerChain.seed || chain.seed == shorterChain.seed {
							delete(dists, key)
						}
					}
					err = reset(chains, longerChain.WID, outBits)
					if err != nil {
						return nil, iterations, 0, time.Since(start), err
					}
					err = reset(chains, shorterChain.WID, outBits)
					if err != nil {
						return nil, iterations, 0, time.Since(start), err
					}
				} else { // если не было такой отличительной точки, то записываем к себе в словарь
					dists[chains[i].val] = chains[i]
				}
			}
		}
	}
	mem := len(dists)*(outBits+3+int(unsafe.Sizeof(chains[0]))) + len(chains)*int(unsafe.Sizeof(chains[0]))*8
	fmt.Printf("Pollard Attack Simulated (%d-bit): Found %d collisions after %d iterations (%s elapsed).\n",
		outBits, len(collisions), iterations, successTime)
	return collisions, iterations, mem, successTime, nil
}

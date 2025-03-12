package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	//"os"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

// --- Константы ---
// Размер куска хэш-функции для нахождения коллизии
const (
	MinOut             = 8
	MaxOut             = 24
	MsgLen             = 16
	DistBits           = 4
	NumWorkers         = 4
	NumCollisionNeeded = 150
	OverheadBytes      = 10
	maxSeenSize        = 10000
)

var OutBitsList = []int{8, 10, 12, 14, 16, 18, 20, 22, 24}
var globalWorkerID int64 = 0

// Структура для хранения пары сообщений, давшей одинаковый хэш
type Collision struct {
	x string
	y string
}

type Chain struct {
	seed  string
	val   string
	steps int
	WID   int
}

type Result struct {
	OutBits    int
	Iterations int
	Passed     time.Duration
	Memory     int
	Collisions []Collision
}

// Усечённая хэш-функция
// выичисляет SHA-256 от msg и возвращает последние outbits бит в виде строки из "0" и "1"
func SHA_xx(msg []byte, outbits int) (string, error) {
	if outbits < MinOut || outbits > MaxOut {
		return "", errors.New("Invalid out vector size")
	}
	hash := sha256.Sum256(msg)
	hashInt := new(big.Int).SetBytes(hash[:])

	mask := new(big.Int).Lsh(big.NewInt(1), uint(outbits))
	mask.Sub(mask, big.NewInt(1)) // 00...0111.111
	result := new(big.Int).And(hashInt, mask)
	return fmt.Sprintf("%0*b", outbits, result), nil
}

func containColl(arr []Collision, data Collision) bool {
	for _, val := range arr {
		if val.x == data.x && val.y == data.y {
			return true
		}
	}
	return false
}

// Атака на основе парадокса о днях рождения
// Ищет num коллизий для усечённой хэш функции
// возвращает список найденных коллизий и кол-во итераций
func birthdayAttack(num int, outBits int) ([]Collision, int, int, time.Duration, error) {
	collisions := []Collision{}
	dict := make(map[string]string)
	iterations := 0
	start := time.Now()
	for len(collisions) < num {
		v := make([]byte, MsgLen)
		if n, err := rand.Read(v); err != nil || n != MsgLen {
			return nil, iterations, 0, time.Since(start), errors.New("failed to generate random vector")
		}
		h, err := SHA_xx(v, outBits)
		if err != nil {
			return nil, iterations, 0, time.Since(start), err
		}
		if prev, ok := dict[h]; ok {
			if prev != hex.EncodeToString(v) && !containColl(collisions, Collision{x: prev, y: hex.EncodeToString(v)}) {
				collisions = append(collisions, Collision{x: prev, y: hex.EncodeToString(v)})
			}
		} else {
			dict[h] = hex.EncodeToString(v)
		}
		iterations++
	}
	passed := time.Since(start)
	mem := len(dict)*outBits + OverheadBytes
	return collisions, iterations, mem, passed, nil
}

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

// randomState генерирует случайное состояние в виде двоичной строки длины outBits.
func randomState(outBits int) (string, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(outBits))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*b", outBits, n), nil
}

// workerChain запускает цепочку: начиная с начального состояния seed, итеративно вычисляет f(x)=TruncatedSHA(x, outBits).
// Как только найдено отличительное значение (isDistinguished==true), отправляет результат в канал.
func doWorker(outBits, distBits, workerID int, stopCh <-chan struct{}) *Chain {
	seed, err := randomState(outBits)
	if err != nil {
		return nil
	}
	current := seed
	steps := 0
	for {
		select {
		case <-stopCh:
			return nil
		default:
		}
		next, err := SHA_xx([]byte(current), outBits)
		if err != nil {
			return nil
		}
		steps++
		current = next
		if isDistinguished(current, distBits) {
			return &Chain{seed: seed, val: current, steps: steps, WID: workerID}
		}
		if steps > 1e6 {
			seed, err = randomState(outBits)
			if err != nil {
				return nil
			}
			current = seed
			steps = 0
		}
	}
}

// spawnWorker всегда выдаёт новый уникальный идентификатор.
func spawnWorker(outBits, distBits int, results chan<- Chain, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	newID := int(atomic.AddInt64(&globalWorkerID, 1))
	wg.Add(1)
	go func(WID int) {
		defer wg.Done()
		chain := doWorker(outBits, distBits, WID, stopCh)
		if chain == nil {
			return
		}
		select {
		case results <- *chain:
		case <-stopCh:
			return
		}
	}(newID)
}

// Атака Полларада(на горутинах)
// при обнаружении двух разных seed, давших совпадающие значения, начинается поиск коллизии
func PollardAttack(outBits int, distinguishedBits int, numColls int, numWorkers int) ([]Collision, int, int, time.Duration, error) {
	resultsCh := make(chan Chain, numWorkers*1000)
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	// Основной сборщик результатов.
	seen := make(map[string]Chain)
	collisions := []Collision{}
	iterations := 0
	// Запускаем ровно numWorkers воркеров, которые работают в цикле
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
				}
				chain := doWorker(outBits, distinguishedBits, id, stopCh)
				if chain == nil {
					continue
				}
				select {
				case resultsCh <- *chain:
				case <-stopCh:
					return
				}
			}
		}(i)
	}
	start := time.Now()

	// Отдельная горутина закрывает resultsCh после завершения всех воркеров.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()
	for {
		select {
		case res, ok := <-resultsCh:
			if !ok {
				goto endLoop
			}
			iterations++
			if res == (Chain{}) {
				continue
			}
			mu.Lock()
			if prev, exists := seen[res.val]; exists {
				//независимо от того совпадают ли сиды или нет
				collisions = append(collisions, Collision{x: prev.seed, y: res.seed})
				fmt.Printf("Collision found: %s = %s (from workers %d and %d, iterations %d vs %d)\n",
					res.val, res.val, prev.WID, res.WID, prev.steps, res.steps)
				if len(collisions) >= numColls {
					close(stopCh)
					mu.Unlock()
					goto endLoop
				}
			} else {
				seen[res.val] = res
			}
			mu.Unlock()
		case <-time.After(10 * time.Second):
			fmt.Println("Still searching for collisions in Pollard Rho...")
		}
	}
endLoop:
	// Закрываем resultsCh после завершения всех воркеров.
	wg.Wait()
	passed := time.Since(start)
	mem := len(seen)*outBits + OverheadBytes
	fmt.Printf("Pollard Rho Attack (parallel, %d-bit, distinguishedBits=%d): Found %d collisions after %d iterations (%s elapsed).\n",
		outBits, distinguishedBits, len(collisions), iterations, passed)
	return collisions, iterations, mem, passed, nil
}

// plotResults строит график и сохраняет его в файл.
func plotResults(title, xLabel, yLabel, filename string, pts plotter.XYs) error {
	p := plot.New()
	p.Title.Text = title
	p.X.Label.Text = xLabel
	p.Y.Label.Text = yLabel
	if err := plotutil.AddLinePoints(p, "data", pts); err != nil {
		return err
	}
	return p.Save(6*vg.Inch, 4*vg.Inch, filename)
}

func main() {
	// Запустим эксперименты для разных значений outBits из outBitsList.
	var bResults []Result
	var pResults []Result

	for _, bits := range OutBitsList {
		fmt.Printf("\n=== Experiment for truncated output = %d bits ===\n", bits)
		// Birthday Attack
		bColls, bIters, bMem, bElapsed, err := birthdayAttack(NumCollisionNeeded, bits)
		if err != nil {
			log.Fatalf("Birthday Attack error for %d bits: %v", bits, err)
		}
		bResults = append(bResults, Result{
			OutBits:    bits,
			Iterations: bIters,
			Passed:     bElapsed,
			Memory:     bMem,
			Collisions: bColls,
		})
		// Pollard Rho Attack (parallel)
		pColls, pIters, pMem, pElapsed, err := PollardAttack(bits, DistBits, NumCollisionNeeded, NumWorkers)
		if err != nil {
			log.Fatalf("Pollard Rho error for %d bits: %v", bits, err)
		}
		pResults = append(pResults, Result{
			OutBits:    bits,
			Iterations: pIters,
			Passed:     pElapsed,
			Memory:     pMem,
			Collisions: pColls,
		})
	}

	// Выводим первые несколько коллизий для наибольшего значения outBits (например, 24 бит)
	fmt.Println("\n=== Sample Collisions for outBits = 24 ===")
	for _, r := range bResults {
		if r.OutBits == 24 {
			fmt.Println("Birthday Attack collisions (first 5):")
			for i, cp := range r.Collisions {
				if i >= 5 {
					break
				}
				fmt.Printf("Collision %d: %s = %s\n", i+1, cp.x, cp.y)
			}
		}
	}
	for _, r := range pResults {
		if r.OutBits == 24 {
			fmt.Println("Pollard Rho Attack collisions (first 5):")
			for i, cp := range r.Collisions {
				if i >= 5 {
					break
				}
				fmt.Printf("Collision %d: %s = %s\n", i+1, cp.x, cp.y)
			}
		}
	}

	// Подготовка данных для построения графиков:
	// По оси X: outBits, по оси Y: среднее время (мс) на одну коллизию и оценка памяти (в байтах).
	bTimePts := make(plotter.XYs, len(bResults))
	bMemPts := make(plotter.XYs, len(bResults))
	pTimePts := make(plotter.XYs, len(pResults))
	pMemPts := make(plotter.XYs, len(pResults))

	for i, res := range bResults {
		avgTime := float64(res.Passed.Milliseconds()) / float64(NumCollisionNeeded)
		bTimePts[i].X = float64(res.OutBits)
		bTimePts[i].Y = avgTime
		bMemPts[i].X = float64(res.OutBits)
		bMemPts[i].Y = float64(res.Memory)
	}
	for i, res := range pResults {
		avgTime := float64(res.Passed.Milliseconds()) / float64(NumCollisionNeeded)
		pTimePts[i].X = float64(res.OutBits)
		pTimePts[i].Y = avgTime
		pMemPts[i].X = float64(res.OutBits)
		pMemPts[i].Y = float64(res.Memory)
	}

	// Строим графики:
	if err := plotResults("Birthday Attack: Average Time vs Output Bits", "Output Bits", "Avg Time (ms)", "birthday_time.png", bTimePts); err != nil {
		log.Fatal(err)
	}
	if err := plotResults("Birthday Attack: Memory vs Output Bits", "Output Bits", "Memory (bytes)", "birthday_mem.png", bMemPts); err != nil {
		log.Fatal(err)
	}
	if err := plotResults("Pollard Rho: Average Time vs Output Bits", "Output Bits", "Avg Time (ms)", "pollard_time.png", pTimePts); err != nil {
		log.Fatal(err)
	}
	if err := plotResults("Pollard Rho: Memory vs Output Bits", "Output Bits", "Memory (bytes)", "pollard_mem.png", pMemPts); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Graphs saved as birthday_time.png, birthday_mem.png, pollard_time.png, pollard_mem.png")
}

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/sagilyp/lab3/mymac"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

type Result struct {
	Algorithm string
	MsgSizeKB float64
	AvgTime   time.Duration
}

func generateRandomMessage(size int) []byte {
	msg := make([]byte, size)
	if _, err := rand.Read(msg); err != nil {
		log.Fatalf("Ошибка генерации сообщения: %v", err)
	}
	return msg
}

func plotResults(title, xLabel, yLabel, filename string, series ...interface{}) error {
	p := plot.New()
	p.Title.Text = title
	p.X.Label.Text = xLabel
	p.Y.Label.Text = yLabel
	if err := plotutil.AddLinePoints(p, series...); err != nil {
		return err
	}
	return p.Save(6*vg.Inch, 4*vg.Inch, filename)
}

func main() {
	msgSizesKB := []float64{0.1, 1, 10, 1024, 2048, 5096, 10192}
	algorithms := []string{mymac.OMAC, mymac.TRUNCATED, mymac.HMAC}
	message := generateRandomMessage(2.5 * mymac.AESBlockSize) // 2.5 блока
	messageAttacked := make([]byte, 2.5*mymac.AESBlockSize)
	copy(messageAttacked, message)
	messageAttacked[0] ^= 0x80 // xor 10000000
	key := generateRandomMessage(16)
	fmt.Printf("Исходное сообщение: %s\n\n", hex.EncodeToString(message))
	for _, alg := range algorithms {
		mm := &mymac.MyMAC{}
		mm.SetMode(alg)
		mm.SetKey(key)
		tag1, err := mm.ComputeMac(message)
		if err != nil {
			log.Fatalf("Ошибка вычисления MAC: %v", err)
		}
		tag2, err := mm.ComputeMac(messageAttacked)
		if err != nil {
			log.Fatalf("Ошибка вычисления MAC: %v", err)
		}
		fmt.Printf("MAC (%s) - оригинальное сообщение: %s\n", alg, hex.EncodeToString(tag1))
		fmt.Printf("MAC (%s) - изменён первый бит: %s\n", alg, hex.EncodeToString(tag2))
		fmt.Printf("Совпадение MAC: %v\n\n", mymac.MacEqual(tag1, tag2))
	}

	var results []Result
	for _, alg := range algorithms {
		if alg == mymac.TRUNCATED {
			continue
		}
		for _, sizeKB := range msgSizesKB {
			msgSize := int(sizeKB * 1024)
			mm := &mymac.MyMAC{}
			if err := mm.SetMode(alg); err != nil {
				log.Fatalf("SetAlgorithm error: %v", err)
			}
			mm.SetKey(key)
			numRuns := 1000
			var duration time.Duration
			for i := 0; i < numRuns; i++ {
				msg := generateRandomMessage(msgSize)
				start := time.Now()
				_, err := mm.ComputeMac(msg)
				if err != nil {
					log.Fatalf("ComputeMac error: %v", err)
				}
				end := time.Since(start)
				duration += end
			}
			avgTime := duration /// time.Duration(numRuns)
			results = append(results, Result{
				Algorithm: alg,
				MsgSizeKB: sizeKB,
				AvgTime:   avgTime,
			})
			fmt.Printf("%s: Message size = %.1f KB, Avg MAC time = %v\n",
				alg, sizeKB, avgTime)
		}
	}
	// построение графиков и подготовка данных
	timePtsOMAC := make(plotter.XYs, 0)
	timePtsHMAC := make(plotter.XYs, 0)
	for _, res := range results {
		switch res.Algorithm {
		case mymac.OMAC:
			timePtsOMAC = append(timePtsOMAC, plotter.XY{X: res.MsgSizeKB, Y: float64(res.AvgTime.Milliseconds())})
		case mymac.HMAC:
			timePtsHMAC = append(timePtsHMAC, plotter.XY{X: res.MsgSizeKB, Y: float64(res.AvgTime.Milliseconds())})
		}
	}
	err := plotResults(
		"Compared Time vs Message Size(1000 msgs)",
		"Message Size (KB)", "Time (ms)",
		"graphs/time_cmp.png",
		"OMAC", timePtsOMAC,
		"HMAC", timePtsHMAC,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = plotResults(
		"OMAC Time vs Message Size(1000 msgs)",
		"Message Size (KB)", "Time (ms)",
		"graphs/time_omac.png",
		"OMAC", timePtsOMAC,
	)
	if err != nil {
		log.Fatal(err)
	}
	err = plotResults(
		"HMAC Time vs Message Size(1000 msgs)",
		"Message Size (KB)", "Time (ms)",
		"graphs/time_hmac.png",
		"HMAC", timePtsHMAC,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Эксперимент успешно завершён. Результаты сохранены")
}

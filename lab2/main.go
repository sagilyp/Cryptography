package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sagilyp/lab2/myattacks"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

var OutBitsList = []int{8, 10, 12, 14, 16, 18, 20, 22, 24}

type Result struct {
	OutBits    int
	Iterations int
	Passed     time.Duration
	Memory     int
	Collisions []myattacks.Collision
}

// plotResults строит график и сохраняет его в файл.
func plotCombinedResults(title, xLabel, yLabel, filename string, series ...interface{}) error {
	p := plot.New()
	p.Title.Text = title
	p.X.Label.Text = xLabel
	p.Y.Label.Text = yLabel

	// series должна быть вида: "Лейбл1", pts1, "Лейбл2", pts2, ...
	if err := plotutil.AddLinePoints(p, series...); err != nil {
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
		//Birthday Attack
		bColls, bIters, bMem, bElapsed, err := myattacks.BirthdayAttack(myattacks.NumCollisionNeeded, bits)
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
		//Pollard Attack
		pColls, pIters, pMem, pElapsed, err := myattacks.PollardAttack(bits, myattacks.DistBits, myattacks.NumCollisionNeeded, myattacks.NumWorkers)
		if err != nil {
			log.Fatalf("Pollard error for %d bits: %v", bits, err)
		}
		pResults = append(pResults, Result{
			OutBits:    bits,
			Iterations: pIters,
			Passed:     pElapsed,
			Memory:     pMem,
			Collisions: pColls,
		})
	}
	collFile, err := os.Create("collisions_24.txt")
	if err != nil {
		log.Fatalf("Cannot create collisions file: %v", err)
	}
	defer collFile.Close()
	collisions24 := pResults[len(pResults)-1].Collisions
	limit := 100
	if len(collisions24) < limit {
		limit = len(collisions24)
	}
	for i := 0; i < limit; i++ {
		hexX, err := myattacks.BinToHex(collisions24[i].X)
		if err != nil {
			log.Fatalf("Cannot write in file: %v", err)
		}
		hexY, err := myattacks.BinToHex(collisions24[i].Y)
		if err != nil {
			log.Fatalf("Cannot write in file: %v", err)
		}
		fmt.Fprintf(collFile, "Collision %d: %s = %s\n", i+1, hexX, hexY)
	}
	fmt.Println("Collisions for 24-bit output saved to collisions_24.txt")

	// Подготовка данных для построения объединённых графиков
	// График времени: ось X – outBits, ось Y – среднее время (мс) на одну коллизию
	bTimePts := make(plotter.XYs, len(bResults))
	pTimePts := make(plotter.XYs, len(pResults))
	for i, res := range bResults {
		avgTime := float64(res.Passed.Milliseconds()) / float64(myattacks.NumCollisionNeeded)
		bTimePts[i].X = float64(res.OutBits)
		bTimePts[i].Y = avgTime
	}
	for i, res := range pResults {
		avgTime := float64(res.Passed.Milliseconds()) / float64(myattacks.NumCollisionNeeded)
		pTimePts[i].X = float64(res.OutBits)
		pTimePts[i].Y = avgTime
	}

	// График памяти: ось X – outBits, ось Y – оценка памяти (в байтах)
	bMemPts := make(plotter.XYs, len(bResults))
	pMemPts := make(plotter.XYs, len(pResults))
	for i, res := range bResults {
		bMemPts[i].X = float64(res.OutBits)
		bMemPts[i].Y = float64(res.Memory)
	}
	for i, res := range pResults {
		pMemPts[i].X = float64(res.OutBits)
		pMemPts[i].Y = float64(res.Memory)
	}

	// Построим объединённые графики (для Birthday Attack и Pollard Rho)
	err = plotCombinedResults(
		"Time vs Output Bits (150 collisions)",
		"Output Bits", "Time (ms)",
		"graphs/time_cmp.png",
		"Birthday Attack", bTimePts,
		"Pollard Attack", pTimePts,
	)
	if err != nil {
		log.Fatal(err)
	}

	err = plotCombinedResults(
		"Memory vs Output Bits (150 collisions)",
		"Output Bits", "Memory (bits)",
		"graphs/memory_cmp.png",
		"Birthday Attack", bMemPts,
		"Pollard Attack", pMemPts,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Graphs saved as combined_time.png and combined_memory.png")
}

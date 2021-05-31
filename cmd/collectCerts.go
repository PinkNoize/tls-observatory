/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/PinkNoize/tls-observatory/internal/dataset"
	"github.com/PinkNoize/tls-observatory/internal/scanner"
	"github.com/PinkNoize/tls-observatory/internal/util"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
)

// collectCertsCmd represents the collectCerts command
var collectCertsCmd = &cobra.Command{
	Use:   "collectCerts",
	Short: "Collects certificate chains from hosts",
	Long:  `Collects certificate chains from hosts in the datasets in output/datasets`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := startCertCollection(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(collectCertsCmd)

	// Here you will define your flags and configuration settings.}
}

func startCertCollection() error {
	db, err := util.PromptDB()
	if err != nil {
		return err
	}
	defer db.Close()
	certCfg, err := configureScan()
	if err != nil {
		return err
	}

	scanner, err := scanner.New(db, certCfg)
	if err != nil {
		return err
	}
	defer scanner.Close()
	stats, err := scanner.Start()
	if err != nil {
		return err
	}
	showProgress(stats)
	fmt.Printf("Successesful host scans: %v\n", stats.Successes)
	fmt.Printf("Failed host scans: %v\n", stats.Errors)
	return nil
}

func configureScan() (*scanner.CertScanConfig, error) {
	sources, err := dataset.GatherDataSources()
	if err != nil {
		return nil, err
	}
	rootNode := tview.NewTreeNode("").
		SetExpanded(true)
	tree := tview.NewTreeView().
		SetRoot(rootNode).
		SetTopLevel(1)
	first := true
	for i, source := range sources {
		node := tview.NewTreeNode(source.Name).
			SetSelectable(true).
			SetColor(tcell.ColorGreen).
			SetExpanded(true).
			SetReference(i)
		if first {
			tree.SetCurrentNode(node)
			first = false
		}
		for _, file := range source.Files {
			childNode := tview.NewTreeNode(file.Name)
			node.AddChild(childNode)
		}
		rootNode.AddChild(node)
	}
	tree.SetSelectedFunc(func(node *tview.TreeNode) {
		ref := node.GetReference()
		switch i := ref.(type) {
		case int:
			if node.GetColor() == tcell.ColorGreen {
				node.SetColor(tcell.ColorRed)
				sources[i].Disable()
			} else {
				node.SetColor(tcell.ColorGreen)
				sources[i].Enable()
			}
		}
	})
	app := tview.NewApplication()

	tree.SetDoneFunc(func(k tcell.Key) {
		if k == tcell.KeyESC {
			app.Stop()
		}
	})

	var timeout string = "5"
	form := tview.NewForm().AddInputField("Timeout (s)", "5", 0,
		func(textToCheck string, lastChar rune) bool {
			if _, err := strconv.Atoi(textToCheck); err != nil {
				return false
			}
			return true
		},
		func(text string) {
			timeout = text
		},
	)

	button := tview.NewButton("Click to start scan or press ESC").
		SetSelectedFunc(func() { app.Stop() })
	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(tree, 0, 1, true).
		AddItem(form, 0, 1, false).
		AddItem(button, 1, 1, false)
	layout.SetBorder(true).
		SetTitle("Enable/Disable data sources").
		SetTitleAlign(tview.AlignCenter)
	if err = app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		return nil, err
	}

	return &scanner.CertScanConfig{
		Sources: sources,
		Timeout: timeout,
	}, nil
}

func formatSources(stats *scanner.CertScanStats, root *tview.TreeNode) {
	progressFile, _ := os.Create("output/progress")
	defer progressFile.Close()
	children := root.GetChildren()
	for _, source := range children {
		for _, node := range source.GetChildren() {
			ref := node.GetReference()
			switch s := ref.(type) {
			case *scanner.FileInfo:
				progress := atomic.LoadInt64(&s.Progress)
				total := atomic.LoadInt64(&s.Total)
				text := fmt.Sprintf(
					"%s [ %d / %d B] %.2f %%",
					s.Name,
					progress,
					total,
					(float32(progress)/float32(total))*100,
				)
				progressFile.WriteString(text + "\n")
				node.SetText(text)
			}
		}
	}
}

func showProgress(stats *scanner.CertScanStats) error {

	zgrabLogWindow := tview.NewTextView().
		SetScrollable(true).
		SetMaxLines(1000)
	zgrabLogWindow.SetBorder(true).
		SetTitle("zgrab2 Log")

	logWindow := tview.NewTextView().
		SetScrollable(true).
		SetMaxLines(1000)
	logWindow.SetBorder(true).
		SetTitle("Log")

	leftWindow := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(logWindow, 0, 1, false).
		AddItem(zgrabLogWindow, 0, 1, false)

	sourceWindow := tview.NewTreeView()
	sourceWindow.SetBorder(true).
		SetTitle("Sources")
	sourceRootNode := tview.NewTreeNode("")
	sourceWindow.SetRoot(sourceRootNode)
	// Add Sources
	for i, source := range stats.SourceStats {
		node := tview.NewTreeNode(source.Name).
			SetExpanded(true).
			SetReference(i)
		for k, file := range source.Files {
			childNode := tview.NewTreeNode(file.Name).
				SetReference(&stats.SourceStats[i].Files[k])
			node.AddChild(childNode)
		}
		sourceRootNode.AddChild(node)
	}

	formatSources(stats, sourceRootNode) // Debug

	statsWindow := tview.NewTable()
	statsWindow.SetBorder(true).
		SetTitle("Stats")
	statsWindow.SetCell(0, 0, tview.NewTableCell("0"))
	statsWindow.SetCell(0, 1, tview.NewTableCell("hosts/s"))
	statsWindow.SetCell(1, 0, tview.NewTableCell("0"))
	statsWindow.SetCell(1, 1, tview.NewTableCell("successes"))
	statsWindow.SetCell(2, 0, tview.NewTableCell("0"))
	statsWindow.SetCell(2, 1, tview.NewTableCell("errors"))

	rightWindow := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sourceWindow, 0, 1, true).
		AddItem(statsWindow, 0, 1, true)

	layout := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(leftWindow, 0, 3, false).
		AddItem(rightWindow, 0, 2, true)

	app := tview.NewApplication()
	// Start zgrab2 log writer
	go func() {
		io.Copy(zgrabLogWindow, stats.ZgrabLog)
	}()
	go func() {
		io.Copy(logWindow, stats.Log)
	}()

	// Stat updating loop
	go func() {
		lastTime := time.Now()
		lastCount := uint64(0)
		for atomic.LoadInt64(&stats.Done) == 0 {
			app.QueueUpdateDraw(func() {
				formatSources(stats, sourceRootNode)
				// domains/s
				successes := atomic.LoadUint64(&stats.Successes)
				errors := atomic.LoadUint64(&stats.Errors)
				now := time.Now()
				nDomains := successes - lastCount
				rate := float64(nDomains) / now.Sub(lastTime).Seconds()
				statsWindow.GetCell(0, 0).SetText(fmt.Sprintf("%.2f", rate))
				lastTime = now
				lastCount = successes
				// successes/errors
				statsWindow.GetCell(1, 0).SetText(fmt.Sprintf("%v", successes))
				statsWindow.GetCell(2, 0).SetText(fmt.Sprintf("%v", errors))
			})
			time.Sleep(time.Second * 1)
		}
		time.Sleep(time.Minute * 2)
		app.Stop()
	}()

	if err := app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		return err
	}
	return nil
}

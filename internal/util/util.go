package util

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PinkNoize/tls-observatory/internal/database"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Strips off the newline
func ReadLine(r *bufio.Reader) ([]byte, error) {
	buf := []byte(nil)
	lineRead := false
	for !lineRead {
		tmp, err := r.ReadBytes('\n')
		switch err {
		case nil:
			if tmp[len(tmp)-1] == '\n' {
				lineRead = true
				tmp = tmp[:len(tmp)-1]
			}
			buf = append(buf, tmp...)
		case io.EOF:
			buf = append(buf, tmp...)
			return buf, err
		default:
			return nil, err
		}
	}
	return buf, nil
}

var FLASH_COLOR = tcell.GetColor("white")

func PromptDB() (*database.Database, error) {
	app := tview.NewApplication()

	// Check if database exists
	db, err := database.OpenDatabase()
	switch err.(type) {
	case nil:
	case *os.PathError:
		// Ask for db creds
		var user = "root"
		var pass = ""
		var hostname = "localhost:27017"
		info := tview.NewTextView().
			SetDynamicColors(true).
			SetWrap(true)
		form := tview.NewForm().
			AddInputField("Username", user, 20, nil, func(t string) {
				user = t
			}).
			AddPasswordField("Password", pass, 20, '*', func(t string) {
				pass = t
			}).
			AddInputField("Hostname", hostname, 20, nil, func(t string) {
				hostname = t
			}).
			AddButton("Save", func() {
				db, err = database.CreateDatabase(user, pass, hostname)
				if err != nil {
					// Flash background
					ogBg := info.GetBackgroundColor()
					info.SetBackgroundColor(FLASH_COLOR)
					time.Sleep(time.Millisecond * 200)
					info.SetBackgroundColor(ogBg)
					info.Clear()
					fmt.Fprintf(info, "[red::b]Configuration Failed: %v", err)
					return
				}
				app.Stop()
			})
		form.SetBorder(true).
			SetTitle("Enter the database configuration").
			SetTitleAlign(tview.AlignCenter)

		layout := tview.NewFlex().
			SetDirection(tview.FlexRow).
			AddItem(form, 0, 1, true).
			AddItem(info, 1, 1, false)
		if err = app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	if db == nil {
		return nil, errors.New("database creation failed")
	}
	return db, nil
}

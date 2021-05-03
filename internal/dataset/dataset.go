package dataset

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/vbauerster/mpb/v6"
	"github.com/vbauerster/mpb/v6/decor"
)

var DATASETS_PATH = "./output/datasets"
var ROOTCAS_PATH = "./output/rootCAs"

type Datasets []struct {
	Name  string `json:"name"`
	Files []struct {
		URL  string `json:"url"`
		File string `json:"file"`
	} `json:"files"`
}

type DataSource struct {
	Name    string
	Enabled bool
	Files   []struct {
		Name string
		Size int64
	}
}

func getDatasets() (Datasets, error) {
	data, err := ioutil.ReadFile("./datasets.json")
	if err != nil {
		return nil, err
	}
	var datasets Datasets
	if err = json.Unmarshal(data, &datasets); err != nil {
		return nil, err
	}
	return datasets, nil
}

func GetRootCerts() error {
	var wg sync.WaitGroup
	p := mpb.New(mpb.WithWaitGroup(&wg))
	tarUrl := "https://nabla-c0d3.github.io/trust_stores_observatory/trust_stores_as_pem.tar.gz"
	if err := os.MkdirAll(ROOTCAS_PATH, 0775); err != nil {
		return err
	}
	bar := p.AddBar(0,
		mpb.PrependDecorators(
			decor.Name("rootCAs.tar.gz", decor.WCSyncSpace),
			decor.CountersKiloByte(" % .2f / % .2f ", decor.WCSyncSpace),
			decor.Percentage(decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.EwmaSpeed(decor.UnitKB, "% .2f", 60),
		),
	)
	fileLoc := "./output/rootCAs/rootCAs.tar.gz"
	wg.Add(1)
	go downloadFile(fileLoc, tarUrl, bar, &wg)
	wg.Wait()
	cmd := exec.Command("tar", "xzvf", fileLoc, "-C", ROOTCAS_PATH)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func DownloadAllDatasets() error {
	datasets, err := getDatasets()
	if err != nil {
		return err
	}
	datasetPath := filepath.Clean(DATASETS_PATH)

	var wg sync.WaitGroup
	p := mpb.New(mpb.WithWaitGroup(&wg))
	for _, set := range datasets {
		// Setup directories
		setPath := filepath.Join(datasetPath, set.Name)
		if err = os.MkdirAll(setPath, 0775); err != nil {
			return err
		}
		for _, file := range set.Files {
			wg.Add(1)
			bar := p.AddBar(0,
				mpb.PrependDecorators(
					decor.Name(file.File, decor.WCSyncSpace),
					decor.CountersKiloByte(" % .2f / % .2f ", decor.WCSyncSpace),
					decor.Percentage(decor.WCSyncSpace),
				),
				mpb.AppendDecorators(
					decor.EwmaSpeed(decor.UnitKB, "% .2f", 60),
				),
			)
			go downloadFile(filepath.Join(setPath, file.File), file.URL, bar, &wg)
		}
	}
	p.Wait()
	return nil
}

func downloadFile(filename, url string, bar *mpb.Bar, wg *sync.WaitGroup) {
	defer wg.Done()
	client := http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return nil
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer resp.Body.Close()

	size, err := strconv.Atoi(resp.Header.Get("Content-Length"))
	if err != nil {
		size = 0
	}
	bar.SetTotal(int64(size), false)
	proxyReader := bar.ProxyReader(resp.Body)
	defer proxyReader.Close()

	out, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer out.Close()

	_, err = io.Copy(out, proxyReader)
	if err != nil {
		log.Fatal(err)
		return
	}
}

func GatherDataSources() ([]DataSource, error) {
	source_dir, err := ioutil.ReadDir(DATASETS_PATH)
	if err != nil {
		return nil, err
	}
	sources := []DataSource{}
	for _, file := range source_dir {
		cur_source := DataSource{
			Name:    file.Name(),
			Files:   nil,
			Enabled: true,
		}
		if file.IsDir() {
			cur_source_dir, err := ioutil.ReadDir(filepath.Join(DATASETS_PATH, file.Name()))
			if err != nil {
				return nil, err
			}
			for _, datafile := range cur_source_dir {
				if !datafile.IsDir() {
					cur_source.Files = append(cur_source.Files,
						struct {
							Name string
							Size int64
						}{
							Name: datafile.Name(),
							Size: datafile.Size(),
						},
					)
				}
			}
		}
		sources = append(sources, cur_source)
	}
	return sources, nil
}

func (source *DataSource) Disable() {
	source.Enabled = false
}

func (source *DataSource) Enable() {
	source.Enabled = true
}

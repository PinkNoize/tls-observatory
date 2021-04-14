package scanner

import (
	"bufio"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/PinkNoize/tls-observatory/internal/database"
	"github.com/PinkNoize/tls-observatory/internal/dataset"
	"github.com/PinkNoize/tls-observatory/internal/util"
)

type CertScanConfig struct {
	Sources []dataset.DataSource
	Timeout string
}

type FileInfo struct {
	Name     string
	Progress int64
	Total    int64
}

type SourceInfo struct {
	Name  string
	Files []FileInfo
}

type CertScanStats struct {
	Done        int64
	ZgrabLog    *os.File
	Log         *io.PipeReader
	SourceStats []SourceInfo
	Successes   uint64
	Errors      uint64
}

type CertScanner struct {
	db         *database.Database
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     io.ReadCloser
	stderr     io.ReadCloser
	logPipe    *os.File
	userLogger *log.Logger
	cfg        *CertScanConfig
	stats      *CertScanStats
	tempDir    string
}

func New(db *database.Database, cfg *CertScanConfig) (*CertScanner, error) {

	dir, err := ioutil.TempDir("", "tls-observatory")
	if err != nil {
		return nil, err
	}
	logFilePath := filepath.Join(dir, "zgrabLog")
	err = syscall.Mkfifo(logFilePath, 0770)
	if err != nil {
		return nil, err
	}
	// Create zmap2 instance
	cmd := exec.Command("zgrab2", "tls", "--log-file", logFilePath, "--timeout", cfg.Timeout)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	stats := CertScanStats{
		Done: 0,
		Log:  nil,
	}
	return &CertScanner{
		db:         db,
		cmd:        cmd,
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		logPipe:    nil,
		userLogger: nil,
		cfg:        cfg,
		stats:      &stats,
		tempDir:    dir,
	}, nil
}

func (scanner *CertScanner) Close() error {
	err := scanner.stdin.Close()
	if err != nil {
		return err
	}
	err = scanner.cmd.Wait()
	if scanner.logPipe != nil {
		scanner.logPipe.Close()
	}
	os.RemoveAll(scanner.tempDir)

	return err
}

func (scanner *CertScanner) Start() (*CertScanStats, error) {
	err := scanner.cmd.Start()
	if err != nil {
		return nil, err
	}
	logFilePath := filepath.Join(scanner.tempDir, "zgrabLog")
	scanner.logPipe, err = os.OpenFile(logFilePath, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		return nil, err
	}
	scanner.stats.ZgrabLog = scanner.logPipe
	r, w := io.Pipe()
	scanner.userLogger = log.New(w, "", log.LstdFlags)
	scanner.stats.Log = r
	// Setup stats
	sourceStats := []SourceInfo{}
	for _, source := range scanner.cfg.Sources {
		if source.Enabled {
			files := []FileInfo{}
			for _, f := range source.Files {
				files = append(files, FileInfo{
					Name:     f.Name,
					Progress: 0,
					Total:    f.Size,
				})
			}
			sourceStats = append(sourceStats, SourceInfo{
				Name:  source.Name,
				Files: files,
			})
		}
	}
	scanner.stats.SourceStats = sourceStats
	// Start the file processor
	go func() {
		for _, source := range sourceStats {
			scanner.processSource(&source)
		}
	}()
	// TODO: Start the result processor
	go scanner.processResults()
	return scanner.stats, nil
}

var domainValidator *regexp.Regexp = regexp.MustCompile(`(?mi)^[\w-\*]*(?:\.[\w-]+)+$`)

// domain must end with .ip6.arpa.
func convertIPv6Arpa(domain string) string {
	revIP := strings.Split(domain[:len(domain)-10], ".")
	var result strings.Builder
	missingNibbles := 32 - len(revIP)
	ctr := 0
	for i := 0; i < missingNibbles; i++ {
		if ctr != 0 && ctr%4 == 0 {
			result.WriteRune(':')
		}
		result.WriteRune('0')
		ctr++
	}
	for i := len(revIP) - 1; i >= 0; i-- {
		if ctr != 0 && ctr%4 == 0 {
			result.WriteRune(':')
		}
		result.WriteString(revIP[i])
		ctr++
	}
	return result.String()
}

func convertToDomains(domain string) ([]string, error) {
	// Get domain type
	if domainValidator.MatchString(domain) {
		if domain[0] == '*' {
			subdomains := [...]string{"www"}
			domainList := make([]string, 0, len(subdomains)+1)
			baseDomain := strings.TrimLeft(domain, "*.")
			// Replace * with subdomains
			for _, pfix := range subdomains {
				var tempDomain strings.Builder
				tempDomain.WriteString(pfix)
				tempDomain.WriteRune('.')
				tempDomain.WriteString(baseDomain)
				domainList = append(domainList, tempDomain.String())
			}
			return domainList, nil
		} else {
			return []string{domain}, nil
		}
	} else if strings.HasSuffix(domain, ".ip6.arpa.") {
		ipDomain := convertIPv6Arpa(domain)
		return []string{ipDomain}, nil
	} else {
		// Probably an IP, IDK let zgrab handle it
		return []string{domain}, nil
	}
}

func specialSourceProcess(line string, name string) string {
	switch name {
	case "rapid7sonar":
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			return parts[0]
		} else {
			return line
		}
	default:
		return line
	}
}

func (scanner *CertScanner) processSource(source *SourceInfo) {
	for i, file := range source.Files {
		func() {
			path := filepath.Join(dataset.DATASETS_PATH, source.Name, file.Name)
			fd, err := os.Open(path)
			if err != nil {
				scanner.userLogger.Println(err)
				return
			}
			defer fd.Close()
			content, err := util.Decompress(fd)
			if err != nil {
				scanner.userLogger.Println(err)
				return
			}
			fileScanner := bufio.NewScanner(content)
			for fileScanner.Scan() {
				line := fileScanner.Text()
				line = specialSourceProcess(line, source.Name)
				domains, err := convertToDomains(line)
				if err != nil {
					scanner.userLogger.Println(err)
					continue
				}
				for _, d := range domains {
					// REMOVE ME
					//scanner.userLogger.Println(d)
					scanner.ScanDomain(d)
				}
				// Update stats
				progress, err := fd.Seek(0, io.SeekCurrent)
				if err != nil {
					scanner.userLogger.Println(err)
					continue
				}
				atomic.StoreInt64(&source.Files[i].Progress, progress)
			}
		}()
	}
	scanner.stdin.Close()
}

func (scanner *CertScanner) processResultLine(line []byte) {
	var jsonData map[string]interface{}
	err := json.Unmarshal(line, &jsonData)
	if err != nil {
		scanner.userLogger.Println(err)
		return
	}
	if data, ok := jsonData["data"]; ok {
		switch tls := data.(type) {
		case map[string]interface{}:
			if tls, ok := tls["tls"]; ok {
				switch status := tls.(type) {
				case map[string]interface{}:
					if status["status"] == "success" {
						// Store data in DB
						err = scanner.db.AddCertInfo(line)
						atomic.AddUint64(&scanner.stats.Successes, 1)
						if err != nil {
							scanner.userLogger.Println(err)
							return
						}
					} else if jsonError, ok := status["error"]; ok {
						scanner.userLogger.Println(jsonError)
						atomic.AddUint64(&scanner.stats.Errors, 1)
						return
					} else {
						scanner.userLogger.Printf("Failed to parse error: %s\n", line)
						return
					}
				default:
					scanner.userLogger.Printf("tls not a dict: %s\n", line)
					return
				}
			}
		default:
			scanner.userLogger.Printf("data not a dict: %s\n", line)
			return
		}
	}
}

func (scanner *CertScanner) processResults() {
	defer atomic.StoreInt64(&scanner.stats.Done, 1)
	bufReader := bufio.NewReader(scanner.stdout)
mainLoop:
	for {
		line, err := util.ReadLine(bufReader)
		switch err {
		case nil:
			// Process line
			scanner.processResultLine(line)
		case io.EOF:
			if len(line) > 0 {
				// Process Line
				scanner.processResultLine(line)
			}
			break mainLoop
		default:
			scanner.userLogger.Println(err)
			break mainLoop
		}
	}

}

func (scanner *CertScanner) ScanDomain(domain string) error {
	_, err := scanner.stdin.Write([]byte(domain + "\n"))
	return err
}

// Contents must be lines of valid domains or IPs
func (scanner *CertScanner) ScanCopy(domains io.Reader) error {
	_, err := io.Copy(scanner.stdin, domains)
	return err
}

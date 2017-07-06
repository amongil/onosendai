// Copyright © 2017 Alvaro Mongil
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

var server string
var idFilename string
var idFile string

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Connect to a blackice server to retrieve a list of reachable hosts",
	Long:  `Connect to a blackice server to retrieve a list of reachable hosts.`,
	Run: func(cmd *cobra.Command, args []string) {
		if server != "" {
			fmt.Printf("Connecting to server <%s>\n", server)
			url := server + "/fingerprint"
			res, err := scanRequest("POST", url, idFilename)
			if err != nil {
				fmt.Printf("Error occurred: %s\n", err.Error())
			} else {
				fmt.Println(res)
			}
		} else {
			fmt.Printf("Usage error: When using the scan command, you must specify a server and an identity file.\n\n")
			fmt.Println("Example usage: onosendai scan -s blackice.maaslabs.com -i ~/.ssh/icebreaker.pem")
		}
	},
}

func init() {
	RootCmd.AddCommand(scanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// scanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	//scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	scanCmd.Flags().StringVarP(&server, "server", "s", "", "blackice Server to connect to")
	scanCmd.Flags().StringVarP(&idFilename, "identity_file", "i", "", "your identity file")
}

func scanRequest(method string, APIURL string, idFilename string) (string, error) {
	// For control over HTTP client headers, redirect policy, and other settings
	client := &http.Client{}

	// Read our identity file and store it
	identity, err := ioutil.ReadFile(idFilename)
	if err != nil {
		return "", err
	}

	// Add our form where the ssh key will be sent on
	form := url.Values{}
	form.Add("identity", string(identity))

	// Form our http request
	req, err := http.NewRequest("POST", APIURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal("NewRequest: ", err)
		return "", err
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Print it for logging
	//fmt.Println(formatRequest(req))

	// Send the request via a client
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error sending the request: ", err.Error())
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	return bodyString, err
}

// formatRequest generates ascii representation of a request
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string
	// Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}

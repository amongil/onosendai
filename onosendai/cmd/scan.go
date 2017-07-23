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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/amongil/blackice/blackice/ec2utils"
	"github.com/spf13/cobra"
)

var server string
var idFilename string
var idFile string

// Instance defines an EC2 instance by some fields
type Instance struct {
	ID        string `json:"InstanceId"`
	PrivateIP string `json:"PrivateIpAddress"`
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Connect to a blackice server to retrieve a list of reachable hosts",
	Long:  `Connect to a blackice server to retrieve a list of reachable hosts.`,
	Run: func(cmd *cobra.Command, args []string) {
		if server != "" {
			fmt.Printf("Connecting to server <%s>\n", server)
			url := server + "/scan"
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
	fingerprint, err := GetFingerprint(identity)
	if err != nil {
		return "", err
	}

	// Add our form where the ssh key will be sent on
	form := url.Values{}
	form.Add("identity", fingerprint)

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
	//bodyString := string(bodyBytes)

	// var bodyJSON []map[string]interface{}
	// json.Unmarshal(bodyBytes, &bodyJSON)

	// var result string
	// for _, instance := range bodyJSON {
	// 	//instanceName := instance["Tags"]["Name"].(string) //TODO
	// 	instanceID := instance["InstanceId"].(string)
	// 	privateIPAddress := instance["PrivateIpAddress"].(string)
	// 	result = fmt.Sprintf("Name: %s. InstanceId: %s. IP: %s", "name", instanceID, privateIPAddress)
	// }
	return string(bodyBytes), err
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

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	nullAsn = asn1.RawValue{Tag: 5}
)

// MarshalPKCS8PrivateKey converts a private key to PKCS#8 encoded form.
// See http://www.rsa.com/rsalabs/node.asp?id=2130 and RFC5208.
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	pkcs := pkcs8{
		Version: 0,
	}

	switch key := key.(type) {
	case *rsa.PrivateKey:
		pkcs.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: nullAsn,
		}
		pkcs.PrivateKey = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		bytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, errors.New("x509: failed to marshal to PKCS#8: " + err.Error())
		}

		pkcs.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyECDSA,
			Parameters: nullAsn,
		}
		pkcs.PrivateKey = bytes
	default:
		return nil, errors.New("x509: PKCS#8 only RSA and ECDSA private keys supported")
	}

	bytes, err := asn1.Marshal(pkcs)
	if err != nil {
		return nil, errors.New("x509: failed to marshal to PKCS#8: " + err.Error())
	}

	return bytes, nil
}

// GetFingerprint return finerprint of ssh-key
func GetFingerprint(pemFile []byte) (string, error) {
	block, _ := pem.Decode(pemFile)

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	keyPKCS8, err := ec2utils.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}

	sha := fmt.Sprintf("% x", sha1.Sum(keyPKCS8))
	sha = strings.Replace(sha, " ", ":", -1)
	return sha, nil
}

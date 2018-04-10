package main

import (
	"fmt"
	"net/http"
)

// CrawlerMaxRedirects sets the maximum number of Redirects to be followed
var CrawlerMaxRedirects uint8 = 10

// Saved Redirects
var lastVia []*http.Request

func openURL(url string) {
	var urls []string
	var rCodes []uint16
	client := &http.Client{
		CheckRedirect: redirectPolicyFunc,
	}
	resp, err := client.Head(url)
	if err != nil && err != http.ErrUseLastResponse {
		//add Error Handling
		fmt.Println("something is wrong")
		panic(err)
	}
	for index, element := range lastVia {
		if index > 0 {
			urls = append(urls, fmt.Sprint(element.Response.Request.URL))
			rCodes = append(rCodes, uint16(element.Response.StatusCode))
		}
	}
	urls = append(urls, fmt.Sprint(resp.Request.URL))
	rCodes = append(rCodes, uint16(resp.StatusCode))

	for index, element := range urls {
		fmt.Print(element)
		if index != len(urls)-1 {
			fmt.Print("->")
		}
	}
	fmt.Printf("\n")
	for index, element := range rCodes {
		fmt.Print(element)
		if index != len(rCodes)-1 {
			fmt.Print("->")
		}
	}
	fmt.Printf("\n")
}

//Save upto CrawlerMaxRedirects Redirects
func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	if len(via) > int(CrawlerMaxRedirects) {
		return http.ErrUseLastResponse
	}
	lastVia = append(via, req)
	return nil
}

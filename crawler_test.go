package main

import (
	"fmt"
	"testing"
)

func TestCrawler(t *testing.T) {
	//creating crawler manager
	config, err := readSQLConfig("sql_config.json")
	if err != nil {
		t.Fatalf("Error occurred while reading the config-file 'sql_config.json': %v", err)
	}
	t.Log("Reading SQL Config completed")

	// Opening Database
	err = openDatabase(config)
	if err != nil {
		t.Fatalf("Error occurred while opening the database: %v", err)
	}
	t.Log("Opening Database completed")
	// Read Domains
	data, err := getDomains()
	if err != nil {
		t.Fatalf("Error occurred while getting the domains: %v", err)
	}

	for _, dom := range data {
		if dom.DomainID == 106 {
			if dom.DomainName == "bondportal.de" {
				t.Log("Reading Domains completed")
			} else {
				t.Errorf("Reading Domains failed. Expected 'bondportal.de' with ID 106 but got '%v'", dom.DomainID)
			}
			break
		}
	}

	// Adding Scan Entries
	var testData []ScanData
	for i := 0; i < 3; i++ {
		testData = append(testData, ScanData{})
	}
	testData[0].DomainID = 1
	testData[1].DomainID = 2
	testData[2].DomainID = 3

	testData[0].DomainReachable = reachableHTTP
	testData[1].DomainReachable = reachableSSL
	testData[2].DomainReachable = reachableBoth

	testData[0].ScanID = -1
	testData[1].ScanID = -1
	testData[2].ScanID = -1

	tt := "CrawlerV" + crawlerVersion
	err = insertScanData([]string{tt}, testData)
	if err != nil {
		t.Fatalf("inserting Scan-Data failed: %v", err)
	}
	defer globalDatabase.Exec(fmt.Sprintf("DELETE FROM %s WHERE ScanID = -1", tt))
	t.Log("Inserting Scan-Data complete")
	// Test getScans
	gSF := true
	id2Name := map[int]string{1: "abnamromarketaccess.com", 2: "abnamromarkets.ch", 3: "abnamromarkets.net"}
	for sID := 1; sID < 4; sID++ {
		doms, err := getScans(tt, 1, statusPending)
		if err != nil {
			t.Fatalf("getScans returned with error: %v", err)
		}
		for _, d := range doms {
			if d.DomainName != id2Name[d.DomainID] {
				gSF = false
				t.Errorf("getScans DomainName doesn't fit to DomainID for DomainID %v and ScanID %v", d.DomainID, sID)
			}
		}
	}
	if gSF {
		t.Log("getScans Test completed")
	}

	// Test prepareScanData
	prepareScanData(tt, 1, scanOnlyHTTP)
	prepareScanData(tt, 2, scanOnlySSL)
	prepareScanData(tt, 3, scanBoth)

	//build manager
}

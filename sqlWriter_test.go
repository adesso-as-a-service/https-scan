package main

import (
	"fmt"
	"testing"

	"github.com/fatih/structs"
)

type SQLTestTableRow struct {
	Bool       bool
	Float      float64
	Integer    int
	String     string
	ScanStatus int
}

func TestSQLWriter(t *testing.T) {
	//readingSQLConfig
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
	for i := 0; i < 9; i++ {
		testData = append(testData, ScanData{})
	}
	testData[0].DomainID = 1
	testData[1].DomainID = 2
	testData[2].DomainID = 3
	testData[3].DomainID = 1
	testData[4].DomainID = 2
	testData[5].DomainID = 3
	testData[6].DomainID = 1
	testData[7].DomainID = 2
	testData[8].DomainID = 3

	testData[0].DomainReachable = reachableHTTP
	testData[1].DomainReachable = reachableSSL
	testData[2].DomainReachable = reachableBoth
	testData[3].DomainReachable = reachableHTTP
	testData[4].DomainReachable = reachableSSL
	testData[5].DomainReachable = reachableBoth
	testData[6].DomainReachable = reachableHTTP
	testData[7].DomainReachable = reachableSSL
	testData[8].DomainReachable = reachableBoth

	testData[0].ScanID = 1
	testData[1].ScanID = 1
	testData[2].ScanID = 1
	testData[3].ScanID = 2
	testData[4].ScanID = 2
	testData[5].ScanID = 2
	testData[6].ScanID = 3
	testData[7].ScanID = 3
	testData[8].ScanID = 3

	tt := "SQLTestTable"
	err = insertScanData([]string{tt}, testData)
	if err != nil {
		t.Fatalf("inserting Scan-Data failed: %v", err)
	}
	defer globalDatabase.Exec("DELETE FROM SQLTestTable")
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

	//Scan With HTTP
	ign, err := getScans(tt, 1, statusIgnored)
	pend, err := getScans(tt, 1, statusPending)
	correct := true
	if len(pend) != 2 || len(ign) != 1 {
		correct = false
		t.Error("prepareScan with onlyHTTP failed because the number of test is not right")
	}
	if ign[0].DomainID != 2 {
		correct = false
		t.Error("prepareScan with onlyHTTP failed by not ignoring reachableSSL")
	}

	for _, d := range pend {
		if d.TestWithSSL {
			correct = false
			t.Errorf("prepareScan with onlyHTTP failed by setting TestWithSSL")
		}
		if d.DomainID != 1 && d.DomainID != 3 {
			correct = false
			t.Errorf("prepareScan with onlyHTTP failed because wrong ID is in pending")
		}
	}

	if correct {
		t.Log("prepareScan is correct for onlyHTTP")
	}

	//Scan With SSL
	ign, err = getScans(tt, 2, statusIgnored)
	pend, err = getScans(tt, 2, statusPending)
	correct = true
	if len(pend) != 2 || len(ign) != 1 {
		correct = false
		t.Error("prepareScan with onlySSL failed because the number of test is not right")
	}
	if len(ign) > 0 && ign[0].DomainID != 1 {
		correct = false
		t.Error("prepareScan with onlySSL failed by not ignoring reachableHTTP")
	}

	for _, d := range pend {
		if !d.TestWithSSL {
			correct = false
			t.Errorf("prepareScan with onlySSL failed by not setting TestWithSSL")
		}
		if d.DomainID != 2 && d.DomainID != 3 {
			correct = false
			t.Errorf("prepareScan with onlySSL failed because wrong ID is in pending")
		}
	}

	if correct {
		t.Log("prepareScan is correct for onlySSL")
	}

	//ScanWithBoth
	ign, err = getScans(tt, 3, statusIgnored)
	pend, err = getScans(tt, 3, statusPending)
	correct = true
	if len(pend) != 4 || len(ign) != 0 {
		correct = false
		t.Error("prepareScan with Both failed because the number of test is not right")
	}
	tws := 0
	for _, d := range pend {

		if d.TestWithSSL {
			tws++
		}

	}

	if tws != 2 {
		correct = false
		t.Errorf("prepareScan with Both failed because not the right amount of scans with SSL")
	}

	if correct {
		t.Log("prepareScan is correct for Both")
	}

	//Test Saving Results
	sr := true
	var where ScanWhereCond
	where.DomainID = pend[0].DomainID
	where.ScanID = 3
	where.TestWithSSL = pend[0].TestWithSSL

	var what, returned SQLTestTableRow
	what.Bool = true
	what.Float = 42.42
	what.Integer = 1337
	what.String = "foobar"
	what.ScanStatus = statusDone

	err = saveResults(tt, structs.New(where), structs.New(what))

	if err != nil {
		sr = false
		t.Errorf("Couldn't save Results because of Error: %v", err)
	}

	res, err := globalDatabase.Query(fmt.Sprintf(
		"SELECT Bool, Float, Integer, String, ScanStatus "+
			"FROM %v "+
			"WHERE ScanID = ? "+
			"AND TestWithSSL = ? "+
			"AND DomainID = ?", tt), where.ScanID, where.TestWithSSL, where.DomainID)
	if err != nil {
		sr = false
		t.Errorf("Couldn't get Results from Database because of Error: %v", err)
	}
	count := 0
	for res.Next() {
		count++
		if count > 1 {
			t.Fatal("To many results from the Database")
		}
		if err := res.Scan(&returned.Bool, &returned.Float, &returned.Integer, &returned.String, &returned.ScanStatus); err != nil {
			t.Fatalf("Couldn't parse return values: %v", err)
		}
	}
	if err := res.Err(); err != nil {
		t.Fatalf("Couldn't get Results from Database because of Error: %v", err)
	}
	if returned != what {
		t.Errorf("Saved value didn't match the expected value:\nreturned: %v\nexpected: %v", returned, what)
	} else if sr {
		t.Log("Saving Results Test completed")
	}
}

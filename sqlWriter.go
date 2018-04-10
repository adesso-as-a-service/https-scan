package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/fatih/structs"
)

var globalDatabase *sql.DB

// maximum number of inserts in one SQLStatement
var maxSQLInserts = 300

// Datatypes

// SQLConfiguration collects the Data needed for Connecting to an SQL-Database
type SQLConfiguration struct {
	SQLServer     string
	SQLUserID     string
	SQLPassword   string
	SQLDatabase   string
	SQLEncryption string
}

// DomainsReachable is the base type for receiving the domains which should be scanned
type DomainsReachable struct {
	DomainID        int
	DomainName      string
	DomainReachable uint8
	TestWithSSL     bool
}

// openDatabase opens the database used for accessing domains and saving results
func openDatabase(conf SQLConfiguration) error {
	var err error
	globalDatabase, err = sql.Open("mssql", fmt.Sprintf("server=%v;user id=%v;password=%v;database=%v;encrypt=%v",
		conf.SQLServer, conf.SQLUserID, conf.SQLPassword, conf.SQLDatabase, conf.SQLEncryption))
	return err
}

// getScans returns all Domains and their Reachability and how they should be tested. They are
// selected by the specified "scanID" and the "ScanStatus"
func getScans(table string, scanID int, scanStatus uint8) []DomainsReachable {
	var result []DomainsReachable
	var help DomainsReachable
	rows, err := globalDatabase.Query(fmt.Sprintf(
		"Select Domains.DomainID, Domains.DomainName, %[1]s.DomainReachable, %[1]s.TestWithSSL "+
			"FROM Domains, %[1]s "+
			"WHERE %[1]s.ScanStatus = ? "+
			"   AND %[1]s.ScanID = ? "+
			"   AND %[1]s.DomainID = Domains.DomainID", table), scanStatus, scanID)
	if err != nil {
		// Better Error Handling needed
		log.Fatal(err)
	}
	for rows.Next() {
		if err := rows.Scan(&help.DomainID, &help.DomainName, &help.DomainReachable, &help.TestWithSSL); err != nil {
			log.Fatal(err)
		}
		result = append(result, help)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	return result
}

// prepareScan modifies the pending scans according to the "scanType". Entries are duplicated with diffrent "TestWithSSL"-Values, if
// both Protocols are supported and wanted. If the wanted Protocol is not supported, they are marked with SCAN_STATUS IGNORED.
func prepareScanData(table string, scanID int, scanType int) error {
	switch scanType {
	case scanOnlySSL:
		err := updateTestWithSSL(table, scanID, reachableSSL, uint8(1))
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, reachableSSL)
		}
		err = updateTestWithSSL(table, scanID, reachableBoth, uint8(1))
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, reachableBoth)
		}
		err = updateScanStatus(table, scanID, reachableHTTP, statusIgnored)
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'ScanStatus' values for table '%v' failed for reachable %v", table, reachableHTTP)
		}
	case scanOnlyHTTP:
		err := updateTestWithSSL(table, scanID, reachableHTTP, uint8(0))
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, reachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, reachableBoth, uint8(0))
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, reachableBoth)
		}
		err = updateScanStatus(table, scanID, reachableSSL, statusIgnored)
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'ScanStatus' values for table '%v' failed for reachable %v", table, reachableSSL)
		}
	case scanBoth:
		err := updateTestWithSSL(table, scanID, reachableHTTP, uint8(0))
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, reachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, reachableSSL, uint8(1))
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, reachableSSL)
		}
		err = duplicateScansWithSSL(table, scanID)
		if err != nil {
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("duplicating  values for table '%v' failed for reachable %v", table, reachableBoth)
		}
	}
	return nil
}

// updateTestWithSSL updates the TestWithSSL field for all entries of one scan that have the specified reachable value
func updateTestWithSSL(table string, scanID int, reachable uint8, updateTo uint8) error {
	_, err := globalDatabase.Exec(fmt.Sprintf(
		"UPDATE %[1]v "+
			"SET TestWithSSL = ? "+
			"WHERE ScanID = ? "+
			"AND DomainReachable = ?", table), updateTo, scanID, reachable)
	return err
}

// updateScanStauts updates the ScanStatus field for all entries of one scan that have the specified reachable value
func updateScanStatus(table string, scanID int, reachable uint8, updateTo int) error {
	_, err := globalDatabase.Exec(fmt.Sprintf(
		"UPDATE %[1]v "+
			"SET ScanStatus = ? "+
			"WHERE ScanID = ? "+
			"AND DomainReachable = ?", table), updateTo, scanID, reachable)
	return err
}

// duplicateScansWithSSL duplicates entries for all Scans with should be scanned on HTTP and HTTPS
func duplicateScansWithSSL(table string, scanID int) error {
	_, err := globalDatabase.Exec(fmt.Sprintf(
		"INSERT INTO %[1]v (ScanID, DomainID, DomainReachable, ScanStatus, TestWithSSL) "+
			"SELECT ScanID, DomainID, DomainReachable, ScanStatus, 1 AS TestWithSSL "+
			"FROM %[1]v "+
			"WHERE ScanID = ? "+
			"AND DomainReachable = ? ", table), scanID, reachableBoth)
	return err
}

// saveResults updates table columns defined by "results" for the row defined by "whereCond". The "whereCond"-Parameters are concatenated by ANDs
func saveResults(table string, whereCond *structs.Struct, results *structs.Struct) error {
	var err error
	set, setArgs := getSetString(results)
	where, whereArgs := getWhereString(whereCond)
	if err != nil {
		return err
	}
	_, err = globalDatabase.Exec(fmt.Sprintf(
		"UPDATE %[1]v "+
			"SET %s "+
			"WHERE %s", table, set, where), append(setArgs, whereArgs))

	return err
}

// getSetString returns the Set-String  for a SQL UPDATE based on the serialized String "results"
func getSetString(results *structs.Struct) (string, []interface{}) {
	var set string
	var args []interface{}
	for index, f := range results.Fields() {
		if index > 0 {
			set += ", "
		}
		set += f.Name() + " = ?"
		args = append(args, f.Value())
	}
	return set, args
}

// getWhereString returns the Where-String for an SQL query. whereCond can only contain used Values
func getWhereString(whereCond *structs.Struct) (string, []interface{}) {
	var where string
	var args []interface{}
	for index, f := range whereCond.Fields() {
		if index > 0 {
			where += " AND "
		}
		where += f.Name() + " = ?"
		args = append(args, f.Value())
	}
	return where, args
}

// insertScanData adds scanData to the scan-Databases
func insertScanData(tables []string, scanData []ScanData) error {
	var pos int
	for pos = maxSQLInserts; pos < len(scanData); pos += maxSQLInserts {
		for _, tab := range tables {
			_, err := globalDatabase.Exec(fmt.Sprintf(
				"INSERT INTO %[1]v (ScanID, DomainID, DomainReachable, ScanStatus) "+
					"VALUES"+strings.Repeat("(?,?,?,?) ,", maxSQLInserts-1)+"(?,?,?,?)", tab),
				sliceScanDataToArgs(scanData[pos-maxSQLInserts:pos], statusPending)...)
			if err != nil {
				return err
			}
		}
	}
	for _, tab := range tables {
		_, err := globalDatabase.Exec(fmt.Sprintf(
			"INSERT INTO %[1]v (ScanID, DomainID, DomainReachable, ScanStatus) "+
				"VALUES"+strings.Repeat("(?,?,?,?) ,", pos-maxSQLInserts-len(scanData)-1)+"(?,?,?,?)", tab),
			sliceScanDataToArgs(scanData[pos-maxSQLInserts:], statusPending)...)
		if err != nil {
			return err
		}
	}
	return nil
}

// sliceScanDataToArgs returns the scanData struct as an interface Slice to use as args...
func sliceScanDataToArgs(scanData []ScanData, scanStatus int) []interface{} {
	var res []interface{}
	for _, sD := range scanData {
		res = append(res, sD.ScanID, sD.DomainID, sD.DomainReachable, scanStatus)
	}
	return res
}

// readSqlConfig extracts the information out of the "sql_config.json" file
func readSQLConfig(file string) (SQLConfiguration, error) {
	configFile, err := os.Open(file)
	var config SQLConfiguration
	if err != nil {
		return config, err
	}
	defer configFile.Close()
	decoder := json.NewDecoder(configFile)
	decoderErr := decoder.Decode(&config)
	if decoderErr != nil {
		return config, decoderErr
	}
	return config, nil
}

func getDomains() ([]DomainsRow, error) {
	var results []DomainsRow
	var help DomainsRow
	rows, err := globalDatabase.Query(
		"Select DomainID, DomainName " +
			"FROM Domains")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		if err := rows.Scan(&help.DomainID, &help.DomainName); err != nil {
			return nil, err
		}
		results = append(results, help)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

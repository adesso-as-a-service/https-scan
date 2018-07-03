package backend

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"../hooks"
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

// openDatabase opens the database used for accessing domains and saving results
func OpenDatabase(conf SQLConfiguration) error {
	var err error
	globalDatabase, err = sql.Open("mssql", fmt.Sprintf("server=%v;user id=%v;password=%v;database=%v;encrypt=%v",
		conf.SQLServer, conf.SQLUserID, conf.SQLPassword, conf.SQLDatabase, conf.SQLEncryption))
	return err
}

// GetScans returns all Domains and their Reachability and how they should be tested. They are
// selected by the specified "scanID" and the "ScanStatus"
func GetScans(table string, scanID int, scanStatus uint8) ([]hooks.DomainsReachable, error) {
	var result []hooks.DomainsReachable
	var help hooks.DomainsReachable
	rows, err := globalDatabase.Query(fmt.Sprintf(
		"SELECT Domains.DomainID, Domains.DomainName, %[1]s.DomainReachable, %[1]s.TestWithSSL "+
			"FROM Domains, %[1]s "+
			"WHERE %[1]s.ScanStatus = ? "+
			"   AND %[1]s.ScanID = ? "+
			"   AND %[1]s.DomainID = Domains.DomainID", table), scanStatus, scanID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		if err := rows.Scan(&help.DomainID, &help.DomainName, &help.DomainReachable, &help.TestWithSSL); err != nil {
			log.Fatal(err)
		}
		result = append(result, help)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// prepareScan modifies the pending scans according to the "scanType". Entries are duplicated with diffrent "TestWithSSL"-Values, if
// both Protocols are supported and wanted. If the wanted Protocol is not supported, they are marked with SCAN_STATUS IGNORED.
func PrepareScanData(table string, scanID int, scanType int) error {
	switch scanType {
	case hooks.ScanOnlySSL:
		err := updateTestWithSSL(table, scanID, hooks.ReachableSSL, uint8(1))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableSSL)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateScanStatus(table, scanID, hooks.ReachableHTTP, hooks.StatusIgnored)
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'ScanStatus' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
	case hooks.ScanOnlyHTTP:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(0))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateScanStatus(table, scanID, hooks.ReachableSSL, hooks.StatusIgnored)
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'ScanStatus' values for table '%v' failed for reachable %v", table, hooks.ReachableSSL)
		}
	case hooks.ScanBoth:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableSSL, uint8(1))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableSSL)
		}
		err = duplicateScansWithSSL(table, scanID)
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("duplicating  values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}

	case hooks.ScanOnePreferHTTP:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(0))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
	case hooks.ScanOnePreferSSL:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			log.Printf("ERROR: %v", err.Error())
			log.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
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

// updateScanStatus updates the ScanStatus field for all entries of one scan that have the specified reachable value
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
			"AND DomainReachable = ? ", table), scanID, hooks.ReachableBoth)
	return err
}

// SaveResults updates table columns defined by "results" for the row defined by "whereCond". The "whereCond"-Parameters are concatenated by ANDs
func SaveResults(table string, whereCond *structs.Struct, results *structs.Struct) error {
	var err error
	set, setArgs := getSetString(results)
	where, whereArgs := getWhereString(whereCond)
	if err != nil {
		// Add errorhandling
		return err
	}
	_, err = globalDatabase.Exec(fmt.Sprintf(
		"UPDATE %[1]v "+
			"SET %s "+
			"WHERE %s", table, set, where), append(setArgs, whereArgs...)...)

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
func InsertScanData(tables []string, scanData []hooks.ScanData) error {
	var pos int
	for pos = maxSQLInserts; pos < len(scanData); pos += maxSQLInserts {
		for _, tab := range tables {
			query := fmt.Sprintf(
				"INSERT INTO %[1]v (ScanID, DomainID, DomainReachable, ScanStatus) "+
					"VALUES "+strings.Repeat("(?,?,?,?) ,", maxSQLInserts-1)+"(?,?,?,?)", tab)
			_, err := globalDatabase.Exec(query,
				sliceScanDataToArgs(scanData[pos-maxSQLInserts:pos], hooks.StatusPending)...)
			if err != nil {
				err = fmt.Errorf("While executing\n%s\n an error occured: %v", query, err)
				return err
			}
		}
	}
	for _, tab := range tables {
		_, err := globalDatabase.Exec(fmt.Sprintf(
			"INSERT INTO %[1]v (ScanID, DomainID, DomainReachable, ScanStatus) "+
				"VALUES "+strings.Repeat("(?,?,?,?) ,", len(scanData)-(pos-maxSQLInserts)-1)+"(?,?,?,?)", tab),
			sliceScanDataToArgs(scanData[pos-maxSQLInserts:], hooks.StatusPending)...)
		if err != nil {
			return err
		}
	}
	return nil
}

// sliceScanDataToArgs returns the scanData struct as an interface Slice to use as args...
func sliceScanDataToArgs(scanData []hooks.ScanData, scanStatus int) []interface{} {
	var res []interface{}
	for _, sD := range scanData {
		res = append(res, sD.ScanID, sD.DomainID, sD.DomainReachable, scanStatus)
	}
	return res
}

// readSqlConfig extracts the information out of the "sql_config.json" file
func ReadSQLConfig(file string) (SQLConfiguration, error) {
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

func GetDomains() ([]hooks.DomainsRow, error) {
	var results []hooks.DomainsRow
	var help hooks.DomainsRow
	rows, err := globalDatabase.Query(
		"SELECT DomainID, DomainName " +
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

// Put this in the controller maybe? For order

// insertNewScan creates a new Entry in the ScanTable and returns the ScanID
func InsertNewScan(scan hooks.ScanRow) (hooks.ScanRow, error) {
	var err error
	rows, err := globalDatabase.Query(
		"INSERT INTO Scans (SSLLabs,SSLLabsVersion,Observatory, ObservatoryVersion, SecurityHeaders, SecurityHeadersVersion, Crawler, CrawlerVersion, Done) "+
			"OUTPUT inserted.ScanID "+
			"VALUES (?,?,?,?,?,?,?,?,0)",
		scan.SSLLabs, scan.SSLLabsVersion, scan.Observatory, scan.ObservatoryVersion, scan.SecurityHeaders, scan.SecurityHeadersVersion, scan.Crawler, scan.CrawlerVersion)
	if err != nil {
		return hooks.ScanRow{}, err
	}
	for rows.Next() {
		if err := rows.Scan(&scan.ScanID); err != nil {
			log.Fatal(err)
		}
	}
	return scan, err
}

// getLastScan returns the specified by Id. If id==0, then it returns the last unfinished scan
func GetLastScan(id int) (hooks.ScanRow, error) {
	var err error
	var query string
	var scan hooks.ScanRow
	query = "SELECT TOP(1) ScanID, SSLLabs,SSLLabsVersion,Observatory, ObservatoryVersion, SecurityHeaders, SecurityHeadersVersion, Crawler, CrawlerVersion " +
		"FROM Scans " +
		"WHERE Done = 0 "
	if id != 0 {
		query += fmt.Sprintf("AND ScanID = %d ", id)
	}
	query += "ORDER BY StartTime DESC "

	rows, err := globalDatabase.Query(
		query)
	if err != nil {
		return hooks.ScanRow{}, err
	}
	for rows.Next() {
		if err := rows.Scan(&scan.ScanID, &scan.SSLLabs, &scan.SSLLabsVersion, &scan.Observatory, &scan.ObservatoryVersion, &scan.SecurityHeaders, &scan.SecurityHeadersVersion); err != nil {
			log.Fatal(err)
		}
	}
	return scan, err
}

//Update the specified Scan
func UpdateScan(scan hooks.ScanRow) error {
	var err error
	_, err = globalDatabase.Exec(
		"UPDATE Scans "+
			"SET Unreachable = ?, Total = ?, Done =? "+
			"WHERE ScanID = ?",
		scan.Unreachable, scan.Total, scan.Done, scan.ScanID)
	return err
}

func SaveCertificates(rows []*hooks.CertificateRow, table string) error {
	ctx := context.Background()
	for _, row := range rows {
		query := `
IF NOT EXISTS (SELECT * FROM %[1]v WHERE Thumbprint = ?)
	BEGIN
		INSERT INTO %[1]v
		(Thumbprint, SerialNumber, Subject, Issuer, SigAlg, RevocationStatus, Issues, KeyStrength, DebianInsecure, NotBefore, NotAfter, NextThumbprint)
		VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	END
ELSE
	BEGIN
		UPDATE  %[1]v
		SET Issues = ?
		WHERE Thumbprint = ?
	END
`
		var err error
		_, err = globalDatabase.ExecContext(ctx,
			fmt.Sprintf(query, table),
			row.Thumbprint, row.Thumbprint, row.SerialNumber, row.Subject, row.Issuer, row.SigAlg, row.RevocationStatus, row.Issues,
			row.KeyStrength, row.DebianInsecure, row.NotBefore, row.NotAfter, row.NextThumbprint, row.Issues, row.Thumbprint)
		if err != nil {
			return err
		}
	}
	return nil
}

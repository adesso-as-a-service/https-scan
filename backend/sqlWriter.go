package backend

import (
	"bytes"
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
var logger = log.New(hooks.LogWriter, "SQLwrt \t", log.Ldate|log.Ltime)

// Datatypes

// SQLConfiguration collects the Data needed for Connecting to an SQL-Database
type SQLConfiguration struct {
	SQLServer     string
	SQLUserID     string
	SQLPassword   string
	SQLDatabase   string
	SQLEncryption string
}

// OpenDatabase opens the database used for accessing domains and saving results
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
			logger.Fatal(err)
		}
		result = append(result, help)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// PrepareScanData modifies the pending scans according to the "scanType". Entries are duplicated with diffrent "TestWithSSL"-Values, if
// both Protocols are supported and wanted. If the wanted Protocol is not supported, they are marked with SCAN_STATUS IGNORED.
func PrepareScanData(table string, scanID int, scanType int) error {
	switch scanType {
	case hooks.ScanOnlySSL:
		err := updateTestWithSSL(table, scanID, hooks.ReachableSSL, uint8(1))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableSSL)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateScanStatus(table, scanID, hooks.ReachableHTTP, hooks.StatusIgnored)
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'ScanStatus' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
	case hooks.ScanOnlyHTTP:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(0))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateScanStatus(table, scanID, hooks.ReachableSSL, hooks.StatusIgnored)
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'ScanStatus' values for table '%v' failed for reachable %v", table, hooks.ReachableSSL)
		}
	case hooks.ScanBoth:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableSSL, uint8(1))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableSSL)
		}
		err = duplicateScansWithSSL(table, scanID)
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("duplicating  values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}

	case hooks.ScanOnePreferHTTP:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(0))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
	case hooks.ScanOnePreferSSL:
		err := updateTestWithSSL(table, scanID, hooks.ReachableHTTP, uint8(0))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableHTTP)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
		}
		err = updateTestWithSSL(table, scanID, hooks.ReachableBoth, uint8(1))
		if err != nil {
			// Add errorhandling
			logger.Printf("[ERROR] %v", err.Error())
			logger.Fatalf("Updating the 'TestWithSSL' values for table '%v' failed for reachable %v", table, hooks.ReachableBoth)
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

// InsertScanData adds scanData to the scan-Databases
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
				err = fmt.Errorf("While executing\n%s\n an error occurred: %v", query, err)
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

// ReadSQLConfig extracts the information out of the "sql_config.json" file
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

// GetDomains returns the active domains, that are in the nextScan
func GetDomains() ([]hooks.DomainsRow, error) {
	var results []hooks.DomainsRow
	var help hooks.DomainsRow
	rows, err := globalDatabase.Query(
		"SELECT DomainID, DomainName " +
			"FROM Domains WHERE nextScan = 1 AND isActive = 1")
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

// InsertNewScan creates a new Entry in the ScanTable and returns the ScanID
func InsertNewScan(scan hooks.ScanRow) (hooks.ScanRow, error) {
	var err error
	rows, err := globalDatabase.Query(
		"INSERT INTO Scans (SSLLabs,SSLLabsVersion,Observatory, ObservatoryVersion, SecurityHeaders, SecurityHeadersVersion, Crawler, CrawlerVersion, Config, Done) "+
			"OUTPUT inserted.ScanID "+
			"VALUES (?,?,?,?,?,?,?,?,?,0)",
		scan.SSLLabs, scan.SSLLabsVersion, scan.Observatory, scan.ObservatoryVersion, scan.SecurityHeaders, scan.SecurityHeadersVersion, scan.Crawler, scan.CrawlerVersion, scan.Config)
	if err != nil {
		return hooks.ScanRow{}, err
	}
	for rows.Next() {
		if err := rows.Scan(&scan.ScanID); err != nil {
			logger.Fatal(err)
		}
	}
	return scan, err
}

// GetLastScan returns the specified by Id. If id==0, then it returns the last unfinished scan
func GetLastScan(id int) (hooks.ScanRow, error) {
	var err error
	var query string
	var scan hooks.ScanRow
	query = "SELECT TOP(1) ScanID, SSLLabs,SSLLabsVersion,Observatory, ObservatoryVersion, SecurityHeaders, SecurityHeadersVersion, Crawler, CrawlerVersion, Config " +
		"FROM Scans " +
		"WHERE Done = 0 "
	if id != -1 {
		query += fmt.Sprintf("AND ScanID = %d ", id)
	}
	query += "ORDER BY StartTime DESC "

	rows, err := globalDatabase.Query(
		query)
	if err != nil {
		return hooks.ScanRow{}, err
	}
	for rows.Next() {
		if err := rows.Scan(&scan.ScanID, &scan.SSLLabs, &scan.SSLLabsVersion, &scan.Observatory, &scan.ObservatoryVersion, &scan.SecurityHeaders, &scan.SecurityHeadersVersion, &scan.Crawler, &scan.CrawlerVersion, &scan.Config); err != nil {
			logger.Fatal(err)
		}
	}
	return scan, err
}

// UpdateScan updates the specified Scan
func UpdateScan(scan hooks.ScanRow) error {
	var err error
	_, err = globalDatabase.Exec(
		"UPDATE Scans "+
			"SET Unreachable = ?, Total = ?, Done =? "+
			"WHERE ScanID = ?",
		scan.Unreachable, scan.Total, scan.Done, scan.ScanID)
	return err
}

// SaveCertificates stores all given Certificates in the Table, while avoiding duplicate entries
func SaveCertificates(rows []*hooks.CertificateRow, table string) error {
	ctx := context.Background()
	for _, row := range rows {
		query := `
IF NOT EXISTS (SELECT * FROM %[1]v WHERE Thumbprint = ?)
	BEGIN
		INSERT INTO %[1]v
		(Thumbprint, SerialNumber, Subject, Issuer, SigAlg, RevocationStatus, Issues, KeyStrength, DebianInsecure, NextThumbprint, ValidFrom, ValidTo, AltNames)
		VALUES
		(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	END
ELSE
	BEGIN
		UPDATE  %[1]v
		SET Issues = ?, ValidFrom = ?, ValidTo = ?, AltNames = ?
		WHERE Thumbprint = ?
	END
`
		var err error
		_, err = globalDatabase.ExecContext(ctx,
			fmt.Sprintf(query, table),
			row.Thumbprint, row.Thumbprint, row.SerialNumber, row.Subject, row.Issuer, row.SigAlg, row.RevocationStatus, row.Issues,
			row.KeyStrength, row.DebianInsecure, row.NextThumbprint, row.ValidFrom, row.ValidTo, row.AltNames, row.Issues, row.ValidFrom, row.ValidTo, row.AltNames, row.Thumbprint)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateDomainsFull updates the Domains-Table with the given domains.
func UpdateDomainsFull(rows []hooks.DomainsRowMetaInfo) error {
	ctx := context.Background()
	query := `
IF NOT EXISTS (SELECT * FROM Domains WHERE DomainName = ?)
	BEGIN
		INSERT INTO Domains
		(DomainName,ListID,IsActive,NextScan)
		VALUES
		(?, ?, ?, ?)
	END
ELSE
	BEGIN
		UPDATE Domains
		SET ListID = ?, IsActive = ?, NextScan = ?
		WHERE DomainName = ?
	END
`
	for _, row := range rows {
		if row.DomainName == "" {
			continue
		}
		var err error
		_, err = globalDatabase.ExecContext(ctx,
			query,
			row.DomainName, row.DomainName, row.ListID, row.IsActive, row.NextScan, row.ListID, row.IsActive, row.NextScan, row.DomainName)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetConflictingDomains returns the domains with conflicting listID in form of a map
func GetConflictingDomains(domains []string, listID string) map[string]hooks.DomainsRowMetaInfo {
	queryBase := `SELECT DomainName, ListID, isActive
				FROM Domains
				WHERE (ListID != ? OR isActive = 0) AND DomainName IN `
	var queryIn bytes.Buffer

	queryIn.WriteString("(")
	for i := 0; i < 99; i++ {
		queryIn.WriteString("?,")
	}
	queryIn.WriteString("?)")
	result := make(map[string]hooks.DomainsRowMetaInfo)
	var list hooks.DomainsRowMetaInfo
	var currentDomains []interface{}
	intDoms := make([]interface{}, len(domains))
	for i, dom := range domains {
		intDoms[i] = dom
	}
	for len(intDoms) > 100 {
		currentDomains, intDoms = intDoms[:100], intDoms[100:]
		rows, err := globalDatabase.Query(queryBase+queryIn.String(), append([]interface{}{listID}, currentDomains...)...)
		if err != nil {
			logger.Fatal(err)
		}
		for rows.Next() {
			if err := rows.Scan(&list.DomainName, &list.ListID, &list.IsActive); err != nil {
				logger.Fatal(err)
			}
			result[list.DomainName] = list
		}
	}
	queryIn.Truncate(2 * len(intDoms))
	queryIn.WriteString(")")
	currentDomains = intDoms
	rows, err := globalDatabase.Query(queryBase+queryIn.String(), append([]interface{}{listID}, currentDomains...)...)
	if err != nil {
		logger.Printf("Query:%s\nparams: %v\n", queryBase+queryIn.String(), append([]interface{}{listID}, currentDomains...))
		logger.Panic(err)
	}
	for rows.Next() {
		if err := rows.Scan(&list.DomainName, &list.ListID, &list.IsActive); err != nil {
			logger.Panic(err)
		}
		result[list.DomainName] = list
	}

	return result
}

// ResetDomains removes all domains from the next Scan
func ResetDomains() error {
	_, err := globalDatabase.Exec(
		"Update Domains " +
			"Set nextScan = 0")
	if err != nil {
		return err
	}
	return nil
}

// ActiveDomainsWithListID sets the active field of all domains in that list to the specified value
func ActiveDomainsWithListID(active bool, ListID string) error {
	_, err := globalDatabase.Exec(
		"Update Domains "+
			"Set isActive = ? WHERE ListID = ?", active, ListID)
	if err != nil {
		return err
	}
	return nil
}

// RemoveDomainsWithListID deletes the specified list
func RemoveDomainsWithListID(ListID string) error {
	_, err := globalDatabase.Exec(
		"Update Domains "+
			"Set ListID = NULL WHERE ListID = ?", ListID)
	if err != nil {
		return err
	}
	return nil
}

// ScanDomainsWithListID adds all domains with the specified ListID to the nextScan
func ScanDomainsWithListID(list string) error {
	_, err := globalDatabase.Exec(
		"Update Domains "+
			"Set nextScan = 1 WHERE ListID = ?", list)
	if err != nil {
		return err
	}
	return nil
}

// ScanDomainsWithProjectID adds all domains with the specified ProjectId to the nextScan
func ScanDomainsWithProjectID(projectId string) error {
	_, err := globalDatabase.Exec(
		"Update Domains "+
			"Set nextScan = 1 WHERE DomainId in (SELECT Domains.DomainID FROM Domains "+
			"JOIN Domain_Project ON Domains.DomainID = Domain_Project.DomainID "+
			"WHERE ProjectID = ?)", projectId)
	if err != nil {
		return err
	}
	return nil
}

// ActiveDomainsWithDomain changes the isActive field to the specified value for the given domain
func ActiveDomainsWithDomain(active bool, domain string) error {
	_, err := globalDatabase.Exec(
		"Update Domains "+
			"Set isActive = ? WHERE DomainName = ?", active, domain)
	if err != nil {
		return err
	}
	return nil
}

// RemoveDomainsWithDomain removes all specified domains from a list
func RemoveDomainsWithDomain(domain string) error {
	_, err := globalDatabase.Exec(
		"Update Domains "+
			"Set ListID = NULL WHERE DomainName = ?", domain)
	if err != nil {
		return err
	}
	return nil
}

// ScanDomainsWithDomain adds the specified domain to the next Scan
func ScanDomainsWithDomain(domain string) error {
	query := `
	IF NOT EXISTS (SELECT * FROM Domains WHERE DomainName = ?)
		BEGIN
			INSERT INTO Domains
			(DomainName,NextScan)
			VALUES
			(?, 1)
		END
	ELSE
		BEGIN
			UPDATE Domains
			SET   NextScan = 1
			WHERE DomainName = ?
		END
	`
	_, err := globalDatabase.Exec(query, domain, domain, domain)
	if err != nil {
		return err
	}
	return nil
}

// RemoveDomainsWithDomainAndList deletes the specified domains from the specified list
func RemoveDomainsWithDomainAndList(domain string, list string) error {
	_, err := globalDatabase.Exec(
		"Update Domains "+
			"Set ListID = NULL WHERE DomainName = ? AND ListID = ?", domain, list)
	if err != nil {
		return err
	}
	return nil
}

// SaveUnreachable stores unreachable Domains in the corresponding table
func SaveUnreachable(scanID int, DomainID int, DNSError bool) error {
	_, err := globalDatabase.Exec(
		"INSERT INTO Unreachable (ScanID, DomainID, DNSError) "+
			"VALUES (?,?,?)", scanID, DomainID, DNSError)
	if err != nil {
		return err
	}
	return nil
}

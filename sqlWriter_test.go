package main

import (
	"testing"
)

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

}

https-scan
============

This tool is a command-line client designed for automated and/or bulk testing of domains with
the SSL Labs API and other APIs. The tool is based on Qualys' ssllabs-scan which is available
[here](https://github.com/ssllabs/ssllabs-scan). The scan results can automatically be saved 
into SQL-Database, if needed.

The following APIs are included at the moment:

* Qualys SSL Labs API (https://www.ssllabs.com/about/terms.html)
* HTTP Observatory API by mozilla (https://observatory.mozilla.org/terms.html)
* Securityheaders.io

Additionally a crawler was added to check the redirects of a domain. 



## Requirements

* Tested with go 10.3
* A running MSSQL-database with the tables as specified [below](#sql-table)

## Usage 

SYNOPSIS
```
    https-scan [options]
```

Adding Domains from a file to a List
```
    https-scan -list string -file file -add
```

Adding Domains from a file to a List
```
    https-scan -list string -file file -add
```

Adding Domains from a file to a List auto-overwriting the current List-Value
```
    https-scan -list string -file file -add -force
```

Adding a single Domain to a List
```
    https-scan -list string -domain string -add
```

Removing Domains from a List
```
    https-scan -list string -file file -remove
```

Setting Domains inactive
```
    https-scan -domain string -file file -inactive
```

Setting Domains active
```
    https-scan -domain string -file file -inactive
```

Starting a scan
```
    https-scan -scan
```

Starting a scan with custom configuration
```
    https-scan -scan -config file
```

Starting a scan with domains from a file
```
    https-scan -scan -file file
```

GENERAL OPTIONS

| Option      | Default value | Description |
| ----------- | ------------- | ----------- |
| -active | false | Set the given domains to active (only active domains are scanned)|
| -add | false | Add the given domains to the specified ListID |
| -continue | false | Continue last scan |
| -domain | | Field to specify a single domain|
| -file | | Field to specify a file containing multiple domains (separated by linebreak)|
| -force | false | Force overwrite, if there are conflicting adds|
| -inactive | false | Set the given domains to inactive (only active domains are scanned)|
| -list | | Field to specify the domains belonging to a ListID |
| -remove | false | Remove the given domains from the specified ListID |
| -scan | false | Scan the given domains|
| -verbosity | info | Configure log verbosity: error, notice, info, debug, or trace|
| -config | file | File to read API-Options from
| -no-crawler | false | Don't use the redirect crawler|
| -no-obs | false | Don't use the Observatory-Scan|
| -no-sechead | false | Don't use the SecurityHeaders-Scan|
| -no-ssllabs | false | Don't use the SSLLabs-Scan|

The APIs can be additionally configured via a config-file in the json-Format. Such a file with the
default values set, can be found [here](defaultConfig.json). The configuration is explained in the
README of each [API](apis/README.md) respectively.

All results will be saved in a database. The database as well as the login credentials have to be 
stored in a file *sql_config.json*. An empty file can be found [here](sql_config.json.example).
The sql_user needs read and write access to the used tables.

Also the logs of the last three calls to the function are stored in the *logs*-folder.

## SQL-Database
<a name="sql-table"></a>
The sql-database consists of:
* a table containing the scan settings for each scan,
* a table containing all domains and their current status,
* a table to log unreachable domains,
* and one table per scan-api (two in case of the ssllabs-scan).

The meaning of the entries for each table column can be found in the README for each api. A more in depth
explanation can be found [here](backend/README.md).


## Structure

After parsing the options and creating an entry in the *Scans*-table, the https-scanner gets the domains
that are in the next scan from the *Domains*-table. For these domains a connectivity test is done to 
port 80 (http) and port 443 (https). Domains that are reachable are added to the scan-tables and the rest
is stored in the Unreachable-table. Now a thread for each scan-api is created. These threads check the 
domains to be scanned and start scanning them based on the domain connectivity. The scan-apis handle 
multiple scan at once by starting a thread for each domain, that is currently scanned. The number of 
parallel scans is limited. If a scan is finished, the results are returned to the master-thread for the 
respective api and are saved to the table. In case of an error the api starts the scan of a domain again 
if the retries number isn't surpassed. The apis send the original thread status reports every 4 seconds. 
If an api doesn't send a status message in 20 seconds, it is assumed dead and the scan is terminated.

## Adding a new API

A short instruction on how to add your own API to the https-scan can be found [here](apis/example).



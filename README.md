ssllabs-scan
============

This tool is a command-line client designed for automated and/or bulk testing of domains with
the SSL Labs API and other APIs. The tool is based on Qualys' ssllabs-scan which is available
here: https://github.com/ssllabs/ssllabs-scan 
The scan results can automatically be saved into SQL-Database, if needed.

The following APIs are included at the moment:

* Qualys SSL Labs API (https://www.ssllabs.com/about/terms.html)
* HTTP Observatory API by mozilla (https://observatory.mozilla.org/terms.html)
* Securityheaders.io

Please familiarize yourself with their terms and conditions before useing the tool. 



## Requirements

* Go >= 1.3

## Usage 

SYNOPSIS
```
    ssllabs-scan [options] hostname
    ssllabs-scan [options] --hostfile file
```

OPTIONS

| Option      | Default value | Description |
| ----------- | ------------- | ----------- |
| --api             | BUILTIN       | API entry point, for example https://www.example.com/api/ |
| --verbosity       | info          | Configure log verbosity: error, info, debug, or trace |
| --quiet           | false         | Disable status messages (logging) |
| --ignore-mismatch | false   | Proceed with assessments on certificate mismatch |
| --json-flat       | false         | Output results in flattened JSON format |
| --hostfile        | none          | File containing hosts to scan (one per line) |
| --usecache        | false         | If true, accept cached results (if available), else force live scan |
| --grade           | false         | Output only the hostname: grade |
| --hostcheck       | false         | If true, host resolution failure will result in a fatal error |
| --no-ssllabs         | false      | If true, the ssllabs-test isn't run |
| --no-ssltest  | false         | If true, the hosts aren't checked for their ssl-capabilities before scanning  |
| --no-observatory  | false         | If true, the observatory-test isn't run |
| --no-securityheaders  | false         | If true, the securityheaders-test isn't run |
| --no-sql  | false         | If true, the results aren't saved to a SQL-table |
| --labs-retries  | 0 | Sets the number of retries per host for the ssllabs-scan in case of failure |
| --sslTest-retries | 1 | Sets the number of retries per host for the sslTest in case of failure |
| --obs-retries  | 1 | Sets the number of retries per host for the observatory-scan in case of failure |
| --secH-retries | 2 | Sets the number of retries per host for the securityheades-scan in case of failure |
| --sql-retries  | 3 | Sets the number of retries if the SQL-connection fails |

All results will be saved in a folder "results" (unless run in quiet mode) and the logs will
be saved in a "log"-folder. Both folders will be created, if not already existing, in the 
execution path. To write the results to a SQL-Database, there needs to be a sql_config.json in
the execution path, containing connection-information. You can find an example-file 
["sql_config.json.example"](./sql_config.json.example) in the git.


## Adding a new API

It is possible to add new APIs to the scanner. Information about how to do that and a framework are 
located in ["NewApi.go"](./NewApi.go.example).      



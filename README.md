# ssh-log-detector
A Python-based tool for analysing SSH authentication logs to detect suspicious activity such as brute-force attacks, password spraying, and compromised accounts.  
Created as part of my Third Year University Scripting module.

## Features

### Failed login analysis
- Counts failed login attempts per IP
- Prints a summary of all failed attempts

### Brute-force detection
- Flags IPs with repeated failed logins 

### Password spraying detection
- Identifies IPs targeting multiple usernames

### Success-after-failure detection
- Flags IPs that:
  - Fail multiple times then successfully authenticate  
    - This often indicates a compromised account.

### IP enrichment
- Uses http://ip-api.com to retrieve:
  - Country
  - City
  - ISP
  - Error messages if lookup fails

## Project Structure
```
ssh-log-detector/
├── detector.py        # Main Python script
├── sample_logs/       # Example SSH logs for testing
│   └── test.log
└── Dockerfile         # Container configuration
```


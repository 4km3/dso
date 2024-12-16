# Checkov Severity Mapper

A Python utility for processing Checkov vulnerability scan results and mapping them to severity levels. This tool takes Checkov JSON output and generates both JSON and CSV reports with proper severity mappings.

## Features

- Maps Checkov findings to severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Processes only failed checks, ignoring passed and skipped checks
- Generates both JSON and CSV output formats
- Provides summary statistics by severity level
- Preserves all unique findings, including multiple occurrences of the same check
- Sorts findings by severity for easy review

## Prerequisites

- Python 3.7 or higher
- Input files:
  - Checkov findings JSON file (`findings.json`)
  - Severity mapping file (`severity.json`)

## Installation

1. Clone this repository or download the script
2. Ensure you have Python 3.7+ installed
3. No additional dependencies required (uses standard library only)

## Usage

1. Place your Checkov output JSON file as `findings.json` in the same directory as the script
2. Place your severity mapping file as `severity.json` in the same directory
3. Run the script:

```bash
python checkov_mapper.py
```

### Input Files

#### findings.json
- Standard Checkov JSON output file containing scan results
- Must include `results.failed_checks` section

#### severity.json
- JSON file mapping Checkov check IDs to severity levels
- Format:
```json
[
  {
    "Policy": "Description of the check",
    "Checkov ID": "CKV_AWS_123",
    "Severity": "HIGH"
  }
]
```

### Output Files

The tool generates two output files with the same base name but different extensions:

#### 1. checkov_findings.json
Detailed JSON report containing:
- List of all findings with severity mappings
- Summary statistics by severity level
- Total number of findings

Example structure:
```json
{
  "findings": [
    {
      "check_id": "CKV_AWS_123",
      "check_name": "Check Description",
      "severity": "HIGH",
      "resource": "aws_resource_name",
      "file_path": "/path/to/file"
    }
  ],
  "summary": {
    "CRITICAL": 0,
    "HIGH": 5,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
  },
  "total_findings": 11
}
```

#### 2. checkov_findings.csv
Spreadsheet-friendly CSV report containing:
- Severity
- Check ID
- Check Name
- Resource
- File Path
- Line Range

## Example Console Output

```
Failed Checks Summary (Passed and Skipped checks excluded):
--------------------------------------------------
CRITICAL: 0
HIGH: 5
MEDIUM: 3
LOW: 2
INFO: 1

Total Findings: 11

Reports generated:
- checkov_findings.json
- checkov_findings.csv
```

## Class Structure

### CheckovSeverityMapper
Main class that handles the processing of findings and generation of reports.

Key methods:
- `process_findings()`: Processes the Checkov findings file
- `generate_summary()`: Creates summary statistics
- `generate_report()`: Generates the JSON report
- `export_to_csv()`: Creates the CSV report

### Finding
Dataclass representing a single finding with attributes:
- check_id
- check_name
- severity
- resource
- file_path
- file_line_range
- code_block

## Error Handling

The script includes error handling for common issues:
- Missing input files
- Invalid JSON format
- General exceptions with informative messages

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

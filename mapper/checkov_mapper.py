import json
import csv
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime

@dataclass
class Finding:
    """Represents a single Checkov finding with its severity."""
    check_id: str
    check_name: str
    severity: str
    resource: str
    file_path: str
    file_line_range: List[int]
    code_block: List[List]

class CheckovSeverityMapper:
    def __init__(self, severity_mapping_file: str, output_basename: str = 'checkov_findings'):
        """Initialize the mapper with severity definitions file."""
        self.severity_mapping = self._load_severity_mapping(severity_mapping_file)
        self.output_basename = output_basename
        
    def _load_severity_mapping(self, filepath: str) -> Dict[str, str]:
        """Load and parse the severity mapping file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                severity_data = json.load(f)
                
            # Create a mapping of Checkov ID to Severity
            severity_mapping = {}
            for item in severity_data:
                checkov_id = item.get('Checkov ID')
                severity = item.get('Severity')
                if checkov_id and severity:
                    severity_mapping[checkov_id] = severity
                    
            if not severity_mapping:
                raise ValueError("No valid mappings found in severity file")
                
            return severity_mapping
            
        except Exception as e:
            print(f"Error loading severity mapping file: {str(e)}")
            raise
    
    def process_findings(self, findings_file: str) -> List[Finding]:
        """Process the SARIF format findings file and return mapped results."""
        with open(findings_file, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
            
        mapped_findings = []
        
        # Process SARIF format
        for run in sarif_data.get('runs', []):
            # Build a rules lookup dictionary
            rules = {
                rule.get('id'): rule
                for rule in run.get('tool', {}).get('driver', {}).get('rules', [])
                if rule.get('id')
            }
            
            # Process results
            for result in run.get('results', []):
                check_id = result.get('ruleId')
                if not check_id or check_id not in self.severity_mapping:
                    continue
                
                # Get the rule details
                rule = rules.get(check_id, {})

                # Get location information
                location = result.get('locations', [{}])[0].get('physicalLocation', {})
                artifact_location = location.get('artifactLocation', {}).get('uri', '')
                region = location.get('region', {})
                start_line = region.get('startLine', 0)
                end_line = region.get('endLine', 0)

                # Create Finding object
                finding = Finding(
                    check_id=check_id,
                    check_name=rule.get('shortDescription', {}).get('text', result.get('message', {}).get('text', '')),
                    severity=self.severity_mapping[check_id],
                    resource=result.get('message', {}).get('text', '').split(' in ')[-1],
                    file_path=artifact_location,
                    file_line_range=[start_line, end_line],
                    code_block=[]  # SARIF doesn't typically include code blocks
                )

                mapped_findings.append(finding)

        return mapped_findings
    
    def split_findings_by_severity(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Split findings into high/critical and other severities."""
        high_critical = []
        other = []
        
        for finding in findings:
            if finding.severity in ['HIGH', 'CRITICAL']:
                high_critical.append(finding)
            else:
                other.append(finding)
                
        return {
            'high_critical': high_critical,
            'other': other
        }

    def _generate_json_report(self, findings: List[Finding]) -> Dict:
        """Generate a JSON report for a set of findings."""
        findings_dict = []
        for f in findings:
            finding_dict = {
                'check_id': f.check_id,
                'check_name': f.check_name,
                'severity': f.severity,
                'resource': f.resource,
                'file_path': f.file_path,
                'line_range': f.file_line_range
            }
            findings_dict.append(finding_dict)

        summary = defaultdict(int)
        for f in findings:
            summary[f.severity] += 1

        return {
            'findings': findings_dict,
            'summary': dict(summary),
            'total_findings': len(findings)
        }

    def _generate_sarif_report(self, findings: List[Finding]) -> Dict:
        """Generate a SARIF report for a set of findings."""
        rules = {}
        results = []
        
        for finding in findings:
            # Create rule if not exists
            if finding.check_id not in rules:
                rules[finding.check_id] = {
                    "id": finding.check_id,
                    "shortDescription": {
                        "text": finding.check_name
                    },
                    "defaultConfiguration": {
                        "level": "error" if finding.severity in ["HIGH", "CRITICAL"] else "warning"
                    },
                    "properties": {
                        "security-severity": "9.0" if finding.severity == "CRITICAL" else
                                           "7.0" if finding.severity == "HIGH" else
                                           "4.0" if finding.severity == "MEDIUM" else
                                           "2.0" if finding.severity == "LOW" else "1.0"
                    }
                }
            
            # Create result
            results.append({
                "ruleId": finding.check_id,
                "level": "error" if finding.severity in ["HIGH", "CRITICAL"] else "warning",
                "message": {
                    "text": f"{finding.check_name} in {finding.resource}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path
                        },
                        "region": {
                            "startLine": finding.file_line_range[0],
                            "endLine": finding.file_line_range[1]
                        }
                    }
                }]
            })
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Checkov",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }]
        }

    def export_reports(self, findings: List[Finding]) -> None:
        """Export findings to separate reports by severity."""
        # Split findings
        split_findings = self.split_findings_by_severity(findings)
        
        # Generate and save JSON reports
        for category, items in split_findings.items():
            if items:  # Only generate if there are findings
                # JSON
                json_output = f"/data/{self.output_basename}_{category}.json"
                with open(json_output, 'w', encoding='utf-8') as f:
                    json.dump(self._generate_json_report(items), f, indent=2)
                
                # SARIF
                sarif_output = f"/data/{self.output_basename}_{category}.sarif"
                with open(sarif_output, 'w', encoding='utf-8') as f:
                    json.dump(self._generate_sarif_report(items), f, indent=2)

def main():
    # Initialize mapper
    mapper = CheckovSeverityMapper('severity.json', 'checkov_findings')
    
    try:
        # Process findings
        findings = mapper.process_findings('/data/results_sarif.sarif')

        # Generate reports
        mapper.export_reports(findings)

        # Count high/critical findings
        high_critical_count = sum(1 for f in findings if f.severity in ['HIGH', 'CRITICAL'])

        # Print summary
        print("\nFindings Summary:")
        print("-" * 50)
        severity_count = defaultdict(int)
        for finding in findings:
            severity_count[finding.severity] += 1

        for severity, count in sorted(severity_count.items()):
            print(f"{severity}: {count}")

        print(f"\nTotal Findings: {len(findings)}")

        if high_critical_count > 0:
            print(f"\nFound {high_critical_count} HIGH/CRITICAL severity issues!")
            sys.exit(1)

        sys.exit(0)

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(2)

if __name__ == "__main__":
    main()

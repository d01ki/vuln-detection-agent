"""
Custom tools for vulnerability detection using nmap and CVE databases.
"""

import json
import nmap
import requests
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from crewai_tools import tool


@tool("Nmap Vulnerability Scanner")
def nmap_scan_tool(target_ip: str, scan_type: str = "vuln") -> str:
    """
    Performs nmap vulnerability scans using --script vuln to detect CVE vulnerabilities.
    
    Args:
        target_ip: Target IP address to scan
        scan_type: Type of scan (vuln, default, etc.)
    
    Returns:
        JSON string containing scan results
    """
    try:
        # Get user confirmation before running scan
        print(f"\n🔍 About to run nmap scan against {target_ip}")
        print(f"Command: nmap -sV --script vuln {target_ip}")
        confirm = input("Do you want to proceed? (y/N): ").strip().lower()
        
        if confirm != 'y':
            return json.dumps({"error": "Scan cancelled by user", "status": "cancelled"})
        
        # Initialize nmap scanner
        nm = nmap.PortScanner()
        
        # Run vulnerability scan
        print(f"Starting nmap scan on {target_ip}...")
        scan_args = f"-sV --script vuln"
        scan_result = nm.scan(target_ip, arguments=scan_args)
        
        # Parse results
        results = {
            "target": target_ip,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "nmap_version": nm.nmap_version(),
            "hosts": {},
            "vulnerabilities": []
        }
        
        # Process each host
        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "protocols": {},
                "vulnerabilities": []
            }
            
            # Process protocols and ports
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()
                host_info["protocols"][protocol] = {}
                
                for port in ports:
                    port_info = nm[host][protocol][port]
                    host_info["protocols"][protocol][port] = {
                        "state": port_info["state"],
                        "name": port_info.get("name", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "script": port_info.get("script", {})
                    }
                    
                    # Extract vulnerabilities from script output
                    if "script" in port_info:
                        for script_name, script_output in port_info["script"].items():
                            if "vuln" in script_name.lower() or "cve" in script_output.lower():
                                vuln_info = {
                                    "port": port,
                                    "protocol": protocol,
                                    "script": script_name,
                                    "output": script_output,
                                    "cves": extract_cves(script_output)
                                }
                                host_info["vulnerabilities"].append(vuln_info)
                                results["vulnerabilities"].append(vuln_info)
            
            results["hosts"][host] = host_info
        
        # Save results to file
        output_file = Path("./data") / f"nmap_scan_{target_ip.replace('.', '_')}_{int(time.time())}.json"
        output_file.parent.mkdir(exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Scan completed. Results saved to: {output_file}")
        
        return json.dumps(results, indent=2)
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "target": target_ip,
            "status": "failed"
        }
        return json.dumps(error_result, indent=2)


def extract_cves(script_output: str) -> List[str]:
    """Extract CVE identifiers from script output."""
    import re
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return list(set(re.findall(cve_pattern, script_output, re.IGNORECASE)))


@tool("CVE Information Lookup")
def cve_lookup_tool(cve_id: str) -> str:
    """
    Looks up CVE vulnerability information from databases.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2020-1472)
        
    Returns:
        JSON string containing CVE information
    """
    try:
        # Clean CVE ID
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith('CVE-'):
            return json.dumps({"error": "Invalid CVE format", "provided": cve_id})
        
        print(f"Looking up CVE information for: {cve_id}")
        
        # Try multiple sources
        cve_info = {
            "cve_id": cve_id,
            "sources": {},
            "summary": "",
            "cvss_score": None,
            "severity": "",
            "references": [],
            "affected_products": []
        }
        
        # Source 1: NVD (National Vulnerability Database)
        try:
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(nvd_url, timeout=10)
            
            if response.status_code == 200:
                nvd_data = response.json()
                if nvd_data.get('vulnerabilities'):
                    vuln = nvd_data['vulnerabilities'][0]['cve']
                    cve_info["sources"]["nvd"] = {
                        "description": vuln.get('descriptions', [{}])[0].get('value', ''),
                        "published": vuln.get('published', ''),
                        "modified": vuln.get('lastModified', ''),
                        "references": [ref.get('url', '') for ref in vuln.get('references', [])]
                    }
                    
                    # Extract CVSS score
                    if 'metrics' in vuln:
                        cvss = vuln['metrics']
                        if 'cvssMetricV31' in cvss:
                            score = cvss['cvssMetricV31'][0]['cvssData']['baseScore']
                            cve_info["cvss_score"] = score
                            cve_info["severity"] = get_severity(score)
                    
                    cve_info["summary"] = cve_info["sources"]["nvd"]["description"]
                    cve_info["references"] = cve_info["sources"]["nvd"]["references"]
                    
        except Exception as e:
            cve_info["sources"]["nvd_error"] = str(e)
        
        # Source 2: MITRE (fallback)
        try:
            mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            cve_info["sources"]["mitre_url"] = mitre_url
        except Exception as e:
            cve_info["sources"]["mitre_error"] = str(e)
        
        # Check if this is Zerologon
        if cve_id == "CVE-2020-1472":
            cve_info["zerologon_info"] = {
                "name": "Zerologon",
                "description": "Critical vulnerability in Windows Netlogon Remote Protocol",
                "impact": "Complete domain takeover",
                "affected": "Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019",
                "exploit_available": True
            }
        
        return json.dumps(cve_info, indent=2)
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "cve_id": cve_id,
            "status": "failed"
        }
        return json.dumps(error_result, indent=2)


def get_severity(cvss_score: float) -> str:
    """Convert CVSS score to severity level."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


@tool("Vulnerability Report Generator")
def report_generator_tool(scan_data: str, target_ip: str) -> str:
    """
    Generates comprehensive vulnerability assessment reports in markdown format.
    
    Args:
        scan_data: JSON string containing scan results
        target_ip: Target IP address
        
    Returns:
        Path to generated report file
    """
    try:
        # Parse scan data
        data = json.loads(scan_data) if isinstance(scan_data, str) else scan_data
        
        # Generate report content
        report_content = generate_markdown_report(data, target_ip)
        
        # Save report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = Path("./data") / f"vulnerability_report_{target_ip.replace('.', '_')}_{timestamp}.md"
        report_file.parent.mkdir(exist_ok=True)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"Report generated: {report_file}")
        return str(report_file)
        
    except Exception as e:
        return f"Error generating report: {str(e)}"


def generate_markdown_report(data: Dict[str, Any], target_ip: str) -> str:
    """Generate markdown report content."""
    
    vulnerabilities = data.get('vulnerabilities', [])
    
    report = f"""# Vulnerability Assessment Report

## Executive Summary

**Target:** {target_ip}  
**Scan Date:** {data.get('scan_time', 'Unknown')}  
**Nmap Version:** {data.get('nmap_version', 'Unknown')}  

## Scan Overview

This report contains the results of an automated vulnerability assessment performed against {target_ip}.

### Summary Statistics

- **Total Hosts Scanned:** {len(data.get('hosts', {}))}
- **Total Vulnerabilities Found:** {len(vulnerabilities)}
- **Scan Method:** Nmap with vulnerability scripts

## Vulnerabilities Detected

"""
    
    if not vulnerabilities:
        report += "No vulnerabilities were detected during this scan.\n\n"
    else:
        for i, vuln in enumerate(vulnerabilities, 1):
            cves = vuln.get('cves', [])
            
            report += f"""### Vulnerability #{i}

**Port:** {vuln.get('port', 'Unknown')}  
**Protocol:** {vuln.get('protocol', 'Unknown')}  
**Script:** {vuln.get('script', 'Unknown')}  

**CVEs Identified:**
"""
            
            if cves:
                for cve in cves:
                    report += f"- {cve}\n"
            else:
                report += "- No specific CVEs identified\n"
            
            report += f"\n**Script Output:**\n```\n{vuln.get('output', 'No output available')}\n```\n\n"
    
    report += "## Host Information\n\n"
    
    for host_ip, host_info in data.get('hosts', {}).items():
        report += f"""### Host: {host_ip}

**Hostname:** {host_info.get('hostname', 'Unknown')}  
**State:** {host_info.get('state', 'Unknown')}  

**Open Ports:**
"""
        
        for protocol, ports in host_info.get('protocols', {}).items():
            report += f"\n**{protocol.upper()} Ports:**\n"
            for port, port_info in ports.items():
                service = port_info.get('name', 'unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                state = port_info.get('state', '')
                
                report += f"- {port}/{protocol} - {service}"
                if product:
                    report += f" ({product}"
                    if version:
                        report += f" {version}"
                    report += ")"
                report += f" [{state}]\n"
    
    report += f"""

## Recommendations

### Immediate Actions

1. **Patch Management:** Apply the latest security patches for all identified vulnerabilities
2. **Network Segmentation:** Implement proper network segmentation to limit exposure
3. **Access Controls:** Review and strengthen access controls for affected services

### Long-term Recommendations

1. **Regular Vulnerability Assessments:** Conduct regular automated vulnerability scans
2. **Security Monitoring:** Implement continuous security monitoring
3. **Incident Response:** Ensure incident response procedures are in place

## Conclusion

This automated vulnerability assessment identified {len(vulnerabilities)} potential security issues. 
Immediate attention should be given to any critical or high-severity vulnerabilities.

---

*Report generated by Vulnerability Detection Agent*  
*Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}*
"""
    
    return report

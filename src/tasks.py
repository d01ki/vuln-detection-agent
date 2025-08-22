"""
CrewAI tasks for vulnerability detection workflow.
"""

from crewai import Task


def create_recon_task(agent, target_ip: str):
    """Create reconnaissance task for vulnerability scanning."""
    return Task(
        description=f"""
        Perform comprehensive vulnerability scanning against target {target_ip}.
        
        Your objectives:
        1. Use nmap vulnerability scanner to scan the target for known vulnerabilities
        2. Focus on identifying CVE vulnerabilities using --script vuln
        3. Document all discovered vulnerabilities and open ports
        4. Save scan results in JSON format for further analysis
        5. Provide a clear summary of findings
        
        Target IP: {target_ip}
        
        Important: Always request user confirmation before executing any scanning commands.
        """,
        agent=agent,
        expected_output="""
        JSON formatted scan results containing:
        - Target information and scan metadata
        - List of open ports and services
        - Identified vulnerabilities with CVE numbers
        - Detailed nmap script output
        - Summary of security findings
        """
    )


def create_cve_analysis_task(agent, scan_results: str):
    """Create CVE analysis task for vulnerability research."""
    return Task(
        description=f"""
        Analyze the vulnerabilities discovered during the reconnaissance phase and provide detailed intelligence.
        
        Your objectives:
        1. Parse the scan results from the reconnaissance phase
        2. For each CVE identified, look up detailed information including:
           - Vulnerability description and impact
           - CVSS score and severity level
           - Affected products and versions
           - Available exploits and references
        3. Pay special attention to critical vulnerabilities like Zerologon (CVE-2020-1472)
        4. Provide risk assessment and prioritization
        5. Research potential exploitation methods and impact
        
        Scan Results to analyze:
        {scan_results}
        """,
        agent=agent,
        expected_output="""
        Comprehensive vulnerability analysis report containing:
        - Detailed CVE information for each vulnerability
        - Risk assessment and CVSS scores
        - Impact analysis and exploitation potential
        - Prioritized list of vulnerabilities by severity
        - Specific information about critical vulnerabilities (e.g., Zerologon)
        """
    )


def create_report_task(agent, target_ip: str):
    """Create report generation task for documentation."""
    return Task(
        description=f"""
        Generate a comprehensive vulnerability assessment report based on all findings.
        
        Your objectives:
        1. Compile all information from reconnaissance and CVE analysis phases
        2. Create a professional markdown-formatted report
        3. Include executive summary suitable for management
        4. Provide detailed technical findings for security teams
        5. Include actionable recommendations and remediation steps
        6. Prioritize findings by risk level
        7. Save the report to the data directory
        
        Target: {target_ip}
        
        The report should be comprehensive, professional, and actionable.
        """,
        agent=agent,
        expected_output="""
        A comprehensive vulnerability assessment report in markdown format including:
        - Executive summary with key findings
        - Detailed vulnerability listings with CVE information
        - Risk assessment and prioritization
        - Technical details and evidence
        - Actionable recommendations for remediation
        - File path to the saved report
        """
    )

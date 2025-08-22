"""
CrewAI agents for vulnerability detection and analysis.
"""

from crewai import Agent
from crewai_tools import tool
from tools import nmap_scan_tool, cve_lookup_tool, report_generator_tool


# Wrap the functions as CrewAI tools
@tool
def nmap_scanner(target_ip: str) -> str:
    """Scan target IP for vulnerabilities using nmap"""
    return nmap_scan_tool(target_ip)


@tool  
def cve_analyzer(cve_id: str) -> str:
    """Look up CVE vulnerability information"""
    return cve_lookup_tool(cve_id)


@tool
def report_generator(scan_data: str, target_ip: str) -> str:
    """Generate vulnerability assessment report"""
    return report_generator_tool(scan_data, target_ip)


def create_recon_agent():
    """Create reconnaissance agent for vulnerability scanning."""
    return Agent(
        role="Security Reconnaissance Specialist",
        goal="Perform comprehensive vulnerability scanning to identify potential security weaknesses",
        backstory="""You are an expert security researcher specializing in network reconnaissance 
        and vulnerability identification. You use nmap and various scanning techniques to discover 
        vulnerabilities in target systems. You are methodical, thorough, and always prioritize 
        accuracy in your assessments.""",
        tools=[nmap_scanner],
        verbose=True,
        allow_delegation=False,
        max_iter=3
    )


def create_cve_analyst_agent():
    """Create CVE analysis agent for vulnerability research."""
    return Agent(
        role="CVE Vulnerability Analyst", 
        goal="Analyze and research CVE vulnerabilities to provide detailed threat intelligence",
        backstory="""You are a cybersecurity analyst specialized in vulnerability research and 
        threat intelligence. You have deep knowledge of CVE databases, vulnerability scoring systems, 
        and the latest security threats. You provide detailed analysis of vulnerabilities including 
        their impact, exploitability, and remediation strategies.""",
        tools=[cve_analyzer],
        verbose=True,
        allow_delegation=False,
        max_iter=5
    )


def create_report_agent():
    """Create report generation agent for documentation."""
    return Agent(
        role="Security Report Analyst",
        goal="Generate comprehensive and actionable vulnerability assessment reports",
        backstory="""You are a security consultant who specializes in creating detailed, 
        professional vulnerability assessment reports. You translate technical findings into 
        clear, actionable recommendations for both technical and management audiences. Your reports 
        are known for their clarity, accuracy, and practical value.""",
        tools=[report_generator],
        verbose=True,
        allow_delegation=False,
        max_iter=3
    )

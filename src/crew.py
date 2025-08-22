"""
Main Crew configuration for vulnerability detection workflow.
"""

import os
from crewai import Crew, Process
from agents import create_recon_agent, create_cve_analyst_agent, create_report_agent
from tasks import create_recon_task, create_cve_analysis_task, create_report_task


class VulnDetectionCrew:
    """Main crew class for coordinating vulnerability detection workflow."""
    
    def __init__(self):
        """Initialize the vulnerability detection crew."""
        # Create agents
        self.recon_agent = create_recon_agent()
        self.cve_analyst_agent = create_cve_analyst_agent()
        self.report_agent = create_report_agent()
        
        # Verify OpenAI API key
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY environment variable is required")
    
    def run(self, target_ip: str) -> str:
        """
        Execute the vulnerability detection workflow.
        
        Args:
            target_ip: Target IP address to scan
            
        Returns:
            Final report summary
        """
        print(f"🚀 Starting vulnerability detection workflow for {target_ip}")
        print("=" * 60)
        
        # Create tasks with target IP
        recon_task = create_recon_task(self.recon_agent, target_ip)
        
        # Note: CVE analysis and report tasks will be created after recon completes
        # This allows us to pass actual scan results between tasks
        
        # Create crew with sequential process
        crew = Crew(
            agents=[self.recon_agent, self.cve_analyst_agent, self.report_agent],
            tasks=[recon_task],  # Start with recon task only
            process=Process.sequential,
            verbose=True,
            memory=True
        )
        
        try:
            # Execute reconnaissance phase
            print("\n🔍 Phase 1: Reconnaissance and Vulnerability Scanning")
            print("-" * 50)
            
            recon_result = crew.kickoff()
            
            print("\n🔬 Phase 2: CVE Analysis and Threat Intelligence")
            print("-" * 50)
            
            # Create CVE analysis task with recon results
            cve_task = create_cve_analysis_task(self.cve_analyst_agent, str(recon_result))
            
            # Create new crew for CVE analysis
            cve_crew = Crew(
                agents=[self.cve_analyst_agent],
                tasks=[cve_task],
                process=Process.sequential,
                verbose=True
            )
            
            cve_result = cve_crew.kickoff()
            
            print("\n📊 Phase 3: Report Generation")
            print("-" * 50)
            
            # Create report task
            report_task = create_report_task(self.report_agent, target_ip)
            
            # Create new crew for report generation
            report_crew = Crew(
                agents=[self.report_agent],
                tasks=[report_task],
                process=Process.sequential,
                verbose=True
            )
            
            report_result = report_crew.kickoff()
            
            # Compile final summary
            summary = f"""
Vulnerability Detection Workflow Completed Successfully!

Target: {target_ip}

Phase 1 - Reconnaissance: ✅ Complete
Phase 2 - CVE Analysis: ✅ Complete  
Phase 3 - Report Generation: ✅ Complete

Final Results:
{report_result}

All results have been saved to the ./data directory.
"""
            
            return summary
            
        except Exception as e:
            error_msg = f"Error during vulnerability detection workflow: {str(e)}"
            print(f"\n❌ {error_msg}")
            return error_msg
    
    def get_crew_info(self) -> dict:
        """Get information about the crew configuration."""
        return {
            "agents": [
                {
                    "role": self.recon_agent.role,
                    "goal": self.recon_agent.goal,
                    "tools": [tool.__class__.__name__ for tool in self.recon_agent.tools]
                },
                {
                    "role": self.cve_analyst_agent.role,
                    "goal": self.cve_analyst_agent.goal,
                    "tools": [tool.__class__.__name__ for tool in self.cve_analyst_agent.tools]
                },
                {
                    "role": self.report_agent.role,
                    "goal": self.report_agent.goal,
                    "tools": [tool.__class__.__name__ for tool in self.report_agent.tools]
                }
            ],
            "process": "Sequential",
            "workflow_phases": [
                "1. Reconnaissance and Vulnerability Scanning",
                "2. CVE Analysis and Threat Intelligence", 
                "3. Report Generation and Documentation"
            ]
        }

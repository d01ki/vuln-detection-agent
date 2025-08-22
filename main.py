#!/usr/bin/env python3
"""
Vulnerability Detection Agent - Main Entry Point

CrewAI-based vulnerability detection tool using nmap and CVE analysis.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add src directory to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from crew import VulnDetectionCrew

def main():
    """Main function to run the vulnerability detection crew."""
    
    # Load environment variables
    load_dotenv()
    
    # Check for required environment variables
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables.")
        print("Please copy .env.example to .env and set your OpenAI API key.")
        sys.exit(1)
    
    # Create data directory if it doesn't exist
    data_dir = Path("./data")
    data_dir.mkdir(exist_ok=True)
    
    # Get target IP from user
    target_ip = input("Enter target IP address (e.g., 192.168.253.100): ").strip()
    
    if not target_ip:
        print("Error: Target IP is required.")
        sys.exit(1)
    
    print(f"Starting vulnerability detection for target: {target_ip}")
    print("-" * 50)
    
    try:
        # Initialize and run the crew
        crew = VulnDetectionCrew()
        result = crew.run(target_ip=target_ip)
        
        print("\n" + "=" * 50)
        print("VULNERABILITY DETECTION COMPLETED")
        print("=" * 50)
        print(f"Results saved to: {data_dir}")
        print(f"\nSummary:\n{result}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

# Vulnerability Detection Agent

CrewAI-based vulnerability detection tool using nmap and CVE analysis.

## Overview

This tool uses CrewAI framework to automate vulnerability detection and analysis:
- Reconnaissance agent for nmap vulnerability scanning
- CVE analysis agent for vulnerability assessment
- Report generation agent for markdown reports

## Requirements

- Python 3.9+
- nmap
- CrewAI
- OpenAI API key

## Installation

```bash
git clone https://github.com/d01ki/vuln-detection-agent.git
cd vuln-detection-agent
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

Enter target IP when prompted (e.g., 192.168.253.100)

## Project Structure

```
vuln-detection-agent/
├── src/
│   ├── agents.py           # CrewAI agents definition
│   ├── tasks.py            # Task definitions
│   ├── tools.py            # Custom tools for nmap and CVE
│   └── crew.py             # Main crew configuration
├── data/                   # Output directory for scan results
├── requirements.txt        # Dependencies
├── main.py                 # Entry point
└── README.md
```

## Features

### Phase 1: Vulnerability Detection
- Automated nmap vulnerability scanning
- CVE information collection and analysis
- JSON-based result sharing between agents
- Human-in-the-loop confirmation for commands

## License

MIT License

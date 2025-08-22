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

### Ubuntu/Debian Setup

```bash
# Clone the repository
git clone https://github.com/d01ki/vuln-detection-agent.git
cd vuln-detection-agent

# Install system dependencies
sudo apt update
sudo apt install python3-full python3-venv nmap

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env file and add your OpenAI API key
nano .env
```

### Other Systems

```bash
git clone https://github.com/d01ki/vuln-detection-agent.git
cd vuln-detection-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
venv\Scripts\activate
# Activate virtual environment (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env file and add your OpenAI API key
```

## Usage

### Quick Start

```bash
# Activate virtual environment (if not already activated)
source venv/bin/activate

# Run the tool
python main.py
```

Enter target IP when prompted (e.g., 192.168.253.100)

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL_NAME=gpt-4
PROJECT_NAME=vuln-detection-agent
OUTPUT_DIR=./data
```

## Project Structure

```
vuln-detection-agent/
├── src/
│   ├── agents.py           # CrewAI agents definition
│   ├── tasks.py            # Task definitions
│   ├── tools.py            # Custom tools for nmap and CVE
│   └── crew.py             # Main crew configuration
├── data/                   # Output directory for scan results
├── venv/                   # Virtual environment (after setup)
├── requirements.txt        # Dependencies
├── main.py                 # Entry point
├── .env.example           # Environment variables template
├── .gitignore
└── README.md
```

## Features

### Phase 1: Vulnerability Detection
- Automated nmap vulnerability scanning
- CVE information collection and analysis
- JSON-based result sharing between agents
- Human-in-the-loop confirmation for commands
- Comprehensive markdown reports

### Workflow

1. **Reconnaissance Phase**
   - Target IP validation
   - Nmap vulnerability scan with `--script vuln`
   - Open port and service detection
   - CVE identification

2. **Analysis Phase**
   - CVE database lookup (NVD, MITRE)
   - CVSS scoring and severity assessment
   - Vulnerability impact analysis
   - Special detection for critical vulnerabilities

3. **Reporting Phase**
   - Executive summary generation
   - Technical findings documentation
   - Actionable recommendations
   - Risk prioritization

## Output Files

- `data/nmap_scan_*.json` - Detailed scan results
- `data/vulnerability_report_*.md` - Comprehensive assessment reports

## Security Considerations

- **Human-in-the-loop**: All scanning commands require user confirmation
- **Controlled Environment**: Designed for authorized testing environments only
- **Ethical Use**: This tool should only be used on systems you own or have explicit permission to test

## Troubleshooting

### Common Issues

1. **Permission Denied for nmap**
   ```bash
   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
   ```

2. **Virtual Environment Issues**
   ```bash
   # Recreate virtual environment
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **OpenAI API Issues**
   - Verify API key in `.env` file
   - Check API quota and billing
   - Ensure internet connectivity

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized use may violate laws and regulations.

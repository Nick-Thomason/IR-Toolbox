# IR-Toolbox

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

An incident response toolbox designed to facilitate rapid, local communication between response teams and operational cells. This locally-hosted solution streamlines the creation and management of standardized incident reports to ensure reliable operation during critical incidents without external dependencies.

## 🚀 Key Features

- **Locally-hosted** with no external dependencies
- **Standardized military-style report generation** (PIR, SPOT, SITREP, RFC, AAR, Vulnerability)
- **Built-in file server** for secure report sharing
- **Portable deployment** - runs from any directory
- **Intuitive text-based user interface**
- **Automatic PDF and TXT report generation**
- **Network-accessible** for team collaboration
- **Dark mode file server** with theme toggle

## 📋 Requirements

- Windows PowerShell
- Python 3.7+
- Administrator privileges (for firewall configuration)

## ⚡ Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Nick-Thomason/IR-Toolbox.git
   cd IR-Toolbox
   ```

2. **Run as Administrator:**
   ```powershell
   # Right-click PowerShell and "Run as Administrator"
   .\launch.ps1
   ```

3. **Access the application:**
   - Main application: `http://[your-ip]:8000`
   - File server: `http://[your-ip]:8001`

## 📊 Report Types

| Report Type | Description | Use Case |
|-------------|-------------|----------|
| **PIR** | Priority Intelligence Requirements | Intelligence gathering and IOC reporting |
| **SPOT** | Situational Report (SALUTE format) | Real-time incident updates |
| **SITREP** | Situation Report | Operational status updates |
| **RFC** | Request for Change | Change management documentation |
| **AAR** | After Action Report | Post-incident analysis |
| **Vulnerability** | Vulnerability Assessment | Security assessment documentation |

## 🛠️ Installation Details

The launch script automatically:
- Sets up a Python virtual environment
- Installs required dependencies
- Configures Windows firewall rules
- Detects network adapter and IP address
- Starts the TUI application and file server

## 📁 Project Structure

```
IR-Toolbox/
├── main.py              # Main Textual TUI application
├── main.tcss            # CSS styling for TUI
├── launch.ps1           # Automated launch script
├── requirements.txt     # Python dependencies
├── files/               # Generated reports directory
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## 🔧 Configuration

The application automatically configures:
- **Port 8000**: Main TUI application
- **Port 8001**: File server for report access
- **Firewall Rules**: Automatically created and managed
- **IP Detection**: Automatically detects WiFi adapter IP

## 📖 Usage

1. **Creating Reports**: Use the tabbed interface to select report type and fill out forms
2. **Viewing Reports**: Click "Current [Report Type]s" buttons or access file server
3. **File Access**: Generated reports available in TXT and PDF formats
4. **Network Sharing**: Other team members can access via your IP address

## 🔒 Security Features

- **Local-only operation** - no external network dependencies
- **Automatic firewall management** - creates only necessary rules
- **Secure file serving** - only TXT and PDF files accessible
- **Admin privilege validation** - ensures proper permissions

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Nicholas Thomason**
- Repository: [https://github.com/Nick-Thomason/IR-Toolbox](https://github.com/Nick-Thomason/IR-Toolbox)
- Contact: [your-contact]

## ⚠️ Classification

**UNCLASSIFIED//FOR OFFICIAL USE ONLY**

## 🙏 Acknowledgments

- Built with [Textual](https://github.com/Textualize/textual) for the TUI interface
- PDF generation powered by [ReportLab](https://www.reportlab.com/)
- Designed for incident response professionals and military personnel

---

*For technical support or feature requests, please open an issue on GitHub.*

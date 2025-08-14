################################################################################
#
#                           IR-TOOLBOX v1.0
#                          Launch Script
#
# Description:    Portable launch script for IR-Toolbox incident reporting tool
#                 Sets up virtual environment, firewall rules, and file server
#                
# Author:         Nicholas Thomason (171 CPT)
# Created:        2025
# License:        MIT License
#
# Requirements:   Windows PowerShell, Python 3.7+, Administrator privileges
# Repository:     https://github.com/[your-repo]
# Contact:        [your-contact]
#
#
################################################################################


$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir
Write-Host "Working directory set to: $scriptDir" -ForegroundColor Cyan
Write-Host "Current user: $env:USERNAME" -ForegroundColor Green

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "Restarting as Administrator for firewall management..." -ForegroundColor Yellow
    Start-Process PowerShell -Verb RunAs -ArgumentList "-ExecutionPolicy", "Bypass", "-Command", "Set-Location '$scriptDir'; & '$($MyInvocation.MyCommand.Path)'"
    exit
}

$mainport = Read-Host "What port will the main.py script run on? aka the TUI (default: 8000)"
if ([string]::IsNullOrWhiteSpace($mainport)) {
    $mainport = "8000"
}
$fileport = Read-Host "What port will the file server run on? (default: 8001)"
if ([string]::IsNullOrWhiteSpace($fileport)) {
    $fileport = "8001"
}


# Kill all existing IR_Reports firewall rules at startup
Write-Host "Removing any existing firewall rules..."
Get-NetFirewallRule -DisplayName "IR_Reports_Port_$mainport" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName "IR_Reports_Port_$fileport" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# Set the path to the virtual environment
$venvPath = ".\venv"

# Kill any processes using ports $mainport and $fileport
@($mainport, $fileport) | ForEach-Object {
    $port = $_
    netstat -ano | Select-String ":$port " | ForEach-Object {
        if ($_ -match '\s+(\d+)$') {
            taskkill /PID $matches[1] /F 2>$null
        }
    }
}

# Create firewall rules for both ports
New-NetFirewallRule -DisplayName "IR_Reports_Port_$mainport" -Direction Inbound -Protocol TCP -LocalPort $mainport -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "IR_Reports_Port_$fileport" -Direction Inbound -Protocol TCP -LocalPort $fileport -Action Allow -Profile Any

# Wait for firewall rules to take effect
Start-Sleep -Seconds 2

# Check if Python is available
try {
    $pythonVersion = python --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    Write-Host "Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "Please install Python 3.7+ and ensure it's in your system PATH" -ForegroundColor Yellow
    Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Cyan
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if the virtual environment exists
if (-Not (Test-Path $venvPath)) {
    Write-Host "Creating virtual environment..."
    python -m venv $venvPath
}

# Activate the virtual environment
Write-Host "Activating virtual environment..."
& "$venvPath\Scripts\Activate.ps1"

# Install dependencies if the requirements file exists
if (Test-Path ".\requirements.txt") {
    Write-Host "Installing dependencies..."
    pip install -r .\requirements.txt
}

# Get WiFi adapter IP address specifically
Write-Host "Detecting WiFi adapter..." -ForegroundColor Yellow

# Method 1: Try to get WiFi adapter by interface description
$wifiAdapter = Get-NetAdapter | Where-Object { 
    $_.Status -eq "Up" -and 
    ($_.InterfaceDescription -like "*Wi-Fi*" -or 
     $_.InterfaceDescription -like "*Wireless*" -or 
     $_.InterfaceDescription -like "*802.11*" -or
     $_.Name -like "*Wi-Fi*" -or
     $_.Name -like "*Wireless*")
}

if (-not $wifiAdapter) {
    # Method 2: Try to get active adapters and filter out Ethernet/VPN
    Write-Host "WiFi adapter not found by name, trying alternative detection..." -ForegroundColor Yellow
    $wifiAdapter = Get-NetAdapter | Where-Object { 
        $_.Status -eq "Up" -and 
        $_.InterfaceDescription -notlike "*Ethernet*" -and
        $_.InterfaceDescription -notlike "*VPN*" -and
        $_.InterfaceDescription -notlike "*Hyper-V*" -and
        $_.InterfaceDescription -notlike "*VMware*" -and
        $_.InterfaceDescription -notlike "*VirtualBox*" -and
        $_.PhysicalMediaType -eq "Native 802.11"
    }
}

if ($wifiAdapter) {
    $wifiIP = Get-NetIPAddress -InterfaceIndex $wifiAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
              Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" }
    
    if ($wifiIP) {
        $currentIP = $wifiIP.IPAddress
        Write-Host "Found WiFi adapter: $($wifiAdapter.Name)" -ForegroundColor Green
        Write-Host "Using WiFi IP: $currentIP" -ForegroundColor Green
    } else {
        Write-Host "WiFi adapter found but no valid IP address detected!" -ForegroundColor Red
        $currentIP = "127.0.0.1"
    }
} else {
    Write-Host "No WiFi adapter detected! Available adapters:" -ForegroundColor Red
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Format-Table Name, InterfaceDescription, LinkSpeed
    
    Write-Host "Falling back to any available IP..." -ForegroundColor Yellow
    $currentIP = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp,Manual -ErrorAction SilentlyContinue | 
                  Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" })[0].IPAddress
    
    if (-not $currentIP) {
        $currentIP = "127.0.0.1"
    }
}

Write-Host "Using IP Address: $currentIP" -ForegroundColor Cyan

# Create the serve.toml for the main application
@"
from textual_serve.server import Server

server = Server("python main.py", port=$mainport, host="$currentIP")
server.serve()
"@ | Out-File -FilePath .\serve.toml -Encoding UTF8

# Create a simple HTTP file server Python script
@"
import http.server
import socketserver
import os
import urllib.parse
from pathlib import Path

class FileServerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='./files', **kwargs)
    
    def list_directory(self, path):
        """Custom directory listing that only shows .txt and .pdf files"""
        try:
            file_list = []
            dir_path = Path(path)
            
            # Get only .txt and .pdf files
            for file_path in dir_path.iterdir():
                if file_path.is_file() and file_path.suffix.lower() in ['.txt', '.pdf']:
                    file_list.append(file_path.name)
            
            file_list.sort()
            
            # Generate HTML response
            html = f'''<!DOCTYPE html>
<html>
<head>
    <title>IR Reports Files</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 40px; 
            background: #1a1a1a; 
            color: #e0e0e0; 
            transition: all 0.3s ease;
        }}
        
        body.light-mode {{ 
            background: #ffffff; 
            color: #333333; 
        }}
        
        .header {{ 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 30px; 
        }}
        
        h1 {{ 
            color: #4fc3f7; 
            margin: 0; 
        }}
        
        body.light-mode h1 {{ 
            color: #1976d2; 
        }}
        
        .theme-toggle {{ 
            background: #333; 
            color: #e0e0e0; 
            border: 2px solid #555; 
            padding: 8px 16px; 
            border-radius: 6px; 
            cursor: pointer; 
            font-size: 14px; 
            transition: all 0.3s ease; 
        }}
        
        .theme-toggle:hover {{ 
            background: #555; 
        }}
        
        body.light-mode .theme-toggle {{ 
            background: #f5f5f5; 
            color: #333; 
            border-color: #ddd; 
        }}
        
        body.light-mode .theme-toggle:hover {{ 
            background: #e0e0e0; 
        }}
        
        .file-list {{ 
            list-style: none; 
            padding: 0; 
        }}
        
        .file-item {{ 
            margin: 10px 0; 
            padding: 15px; 
            background: #2d2d2d; 
            border-radius: 8px;
            display: flex;
            align-items: center;
            transition: all 0.3s ease;
            border: 1px solid #444;
        }}
        
        .file-item:hover {{ 
            background: #3d3d3d; 
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        
        body.light-mode .file-item {{ 
            background: #f8f9fa; 
            border-color: #e9ecef;
        }}
        
        body.light-mode .file-item:hover {{ 
            background: #e9ecef; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .file-link {{ 
            text-decoration: none; 
            color: #81c784; 
            font-weight: bold;
            flex: 1;
            transition: color 0.3s ease;
        }}
        
        .file-link:hover {{ 
            color: #a5d6a7; 
        }}
        
        body.light-mode .file-link {{ 
            color: #2e7d32; 
        }}
        
        body.light-mode .file-link:hover {{ 
            color: #1b5e20; 
        }}
        
        .file-type {{ 
            background: #007acc; 
            color: white; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 12px; 
            margin-left: 10px;
            font-weight: bold;
        }}
        
        .pdf {{ background: #e53935; }}
        .txt {{ background: #43a047; }}
        
        .footer {{ 
            margin-top: 30px; 
            padding-top: 20px; 
            border-top: 1px solid #444; 
        }}
        
        body.light-mode .footer {{ 
            border-top-color: #e9ecef; 
        }}
        
        .footer a {{ 
            color: #4fc3f7; 
        }}
        
        body.light-mode .footer a {{ 
            color: #1976d2; 
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>IR-Toolbox Files</h1>
        <button class="theme-toggle" onclick="toggleTheme()">Light Mode</button>
    </div>
    <p>Available .txt and .pdf files:</p>
    <ul class="file-list">'''
            
            for filename in file_list:
                file_ext = Path(filename).suffix.lower()[1:]  # Remove the dot
                encoded_name = urllib.parse.quote(filename)
                html += f'''
        <li class="file-item">
            <a href="{encoded_name}" class="file-link">{filename}</a>
            <span class="file-type {file_ext}">{file_ext.upper()}</span>
        </li>'''
            
            html += '''
</ul>
    <div class="footer">
        <p><small>Main application: <a href="http://{0}:9000">http://{0}:9000</a></small></p>
    </div>
    
    <script>
        function toggleTheme() {{
            const body = document.body;
            const button = document.querySelector('.theme-toggle');
            
            if (body.classList.contains('light-mode')) {{
                body.classList.remove('light-mode');
                button.textContent = 'Light Mode';
                localStorage.setItem('theme', 'dark');
            }} else {{
                body.classList.add('light-mode');
                button.textContent = 'Dark Mode';
                localStorage.setItem('theme', 'light');
            }}
        }}
        
        // Load saved theme on page load
        document.addEventListener('DOMContentLoaded', function() {{
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme === 'light') {{
                document.body.classList.add('light-mode');
                document.querySelector('.theme-toggle').textContent = 'Dark Mode';
            }}
        }});
    </script>
</body>
</html>'''.format('$currentIP')
            
            return html.encode('utf-8')
            
        except OSError:
            return b"Error: Could not access files directory"
    
    def do_GET(self):
        # Check if requesting root directory
        if self.path == '/' or self.path == '':
            # Generate and send custom directory listing
            content = self.list_directory('./files')
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            # For file requests, check if it's a valid file type
            requested_file = self.path.lstrip('/')
            file_path = Path('./files') / requested_file
            
            if file_path.exists() and file_path.suffix.lower() in ['.txt', '.pdf']:
                super().do_GET()
            else:
                self.send_error(404, "File not found or not allowed")

# Ensure files directory exists
files_dir = Path('./files')
if not files_dir.exists():
    files_dir.mkdir(exist_ok=True)
    print("Created ./files directory")

# Start the file server
HOST = "$currentIP"
PORT = $fileport
with socketserver.TCPServer((HOST, PORT), FileServerHandler) as httpd:
    print(f"File server running at http://{HOST}:{PORT}")
    print("Serving .txt and .pdf files from ./files directory")
    httpd.serve_forever()
"@ | Out-File -FilePath .\file_server.py -Encoding UTF8

# Ensure files directory exists
if (-Not (Test-Path ".\files")) {
    New-Item -ItemType Directory -Path ".\files" -Force
    Write-Host "Created ./files directory" -ForegroundColor Green
}

Get-NetFirewallRule -DisplayName "IR_Reports_Port_$mainport", "IR_Reports_Port_$fileport" -ErrorAction SilentlyContinue | Format-Table DisplayName, Enabled, Direction, Action -AutoSize

Write-Host "To manually remove firewall rules later, run:" -ForegroundColor Yellow
Write-Host "Get-NetFirewallRule -DisplayName 'IR_Reports_Port_$mainport' | Remove-NetFirewallRule" -ForegroundColor Cyan
Write-Host "Get-NetFirewallRule -DisplayName 'IR_Reports_Port_$fileport' | Remove-NetFirewallRule" -ForegroundColor Cyan

# Show current network configuration
Write-Host "`nCurrent Network Configuration:" -ForegroundColor Magenta
Write-Host "Main application: http://$currentIP`:$mainport" -ForegroundColor Green
Write-Host "File server: http://$currentIP`:$fileport" -ForegroundColor Green

# Start the file server in background
Write-Host "`nStarting file server on port $fileport..." -ForegroundColor Yellow
Start-Process python -ArgumentList ".\file_server.py" -WindowStyle Minimized

# Wait a moment for file server to start
Start-Sleep -Seconds 3

# Run the main Python program
Write-Host "`nLaunching main application on port $mainport...`n" -ForegroundColor Yellow
python .\serve.toml
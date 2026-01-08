# 🔍 Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![GUI](https://img.shields.io/badge/GUI-Tkinter-orange.svg)

**Professional Web Vulnerability Scanner**

---

## 📋 Table of Contents
- [✨ Features](#-features)
- [🛠️ Installation](#️-installation)
- [🚀 Usage](#-usage)
- [🎯 Detection Capabilities](#-detection-capabilities)
- [📊 Screenshots](#-screenshots)
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)
- [🔧 Technical Details](#-technical-details)
- [🤝 Contributing](#-contributing)
- [📝 License](#-license)

---

## ✨ Features

### 🎨 **Modern GUI Interface**
- Dark theme with color-coded severity indicators
- Tabbed interface (Results, Details, Statistics, Logs)
- Real-time progress tracking
- Interactive vulnerability treeview
- Export functionality (TXT reports)

### 🛡️ **Comprehensive Vulnerability Detection**
- **SQL Injection** (6 different techniques)
- **Cross-Site Scripting (XSS)**
- **Local/Remote File Inclusion (LFI/RFI)**
- **Command Injection**
- **Missing Security Headers**
- **SSL/TLS Configuration Issues**

### 🔍 **Advanced SQLi Detection Methods**
- ✅ **Error-based SQLi** - Detects database error messages
- ✅ **Boolean-based SQLi** - Response comparison analysis
- ✅ **Time-based SQLi** - Response timing analysis
- ✅ **Union-based SQLi** - UNION SELECT payload testing
- ✅ **Blind SQLi** - Blind injection detection
- ✅ **Stacked Queries** - Multiple query execution testing

### ⚡ **Smart Features**
- Auto-spidering for URL/Form discovery
- Concurrent scanning with thread management
- Customizable scan intensity (Low/Medium/High/Aggressive)
- Batch target loading from file
- Detailed vulnerability logging
- Real-time statistics generation

---

## 🛠️ Installation


### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone https://github.com/12bijaya/Vulnereability_SCANNER.git
cd Vulnereability_SCANNER

# 2. Install required packages
pip install -r requirements.txt

# 3. Run the scanner
python scanner.py




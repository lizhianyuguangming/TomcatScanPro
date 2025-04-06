# TomcatScanPro

README Version: [简体中文](README.md)

## Introduction

This project is a weak password detection tool for **Tomcat** services. It supports multiple exploitation methods for **CVE-2017-12615** vulnerability and integrates **CNVD-2020-10487** (Tomcat AJP protocol local file inclusion vulnerability) exploitation capabilities, helping users efficiently detect vulnerabilities and obtain server sensitive information. The tool supports concurrent detection of multiple URLs and optimizes resource utilization through dynamic thread pool mechanism.

## Features

### 1. **CVE-2017-12615 Vulnerability Detection**
   - Supports three exploitation methods:

      `PUT /1.jsp/`
     
      `PUT /1.jsp%20`
     
      `PUT /1.jsp::$DATA`
     
   - After successful upload, the tool will attempt to access and execute the uploaded JSP file to verify remote code execution capability.
   - Records success/failure status for each exploitation method separately.

### 2. **CNVD-2020-10487 (AJP Protocol LFI Vulnerability)**
   - Utilizes AJP protocol for local file inclusion attacks, default reading WEB-INF/web.xml file with configurable file paths and detection conditions.
   - Supports custom keyword matching (e.g. "Welcome") to determine successful file read.
   - Records successful URLs and sensitive file paths in detail.

### 3. **Weak Password Detection**
   - Performs brute-force attacks using username-password combinations.
   - Automatically uploads WebShell upon successful login for remote management.
   - Logs successful logins and WebShell upload results.

### 4. **WAR Package Deployment `getshell`**
   - Uploads WAR package through Tomcat management console after successful login.
   - Deployed WAR package automatically generates JSP Shell for remote code execution.
   - Supports custom Shell content through configuration file.

## Usage

1. Prepare text files containing URLs, usernames and passwords named `urls.txt`, `user.txt` and `passwd.txt` respectively.
2. `urls.txt` format: https://127.0.0.1/ or https://127.0.0.1/manager/html (automatic detection)
3. Configure file paths and settings in `config.yaml`
4. Run script (successful exploits will be recorded in `success.txt`):

   ```bash
   python TomcatScanPro.py
   ```

![Demo](https://github.com/user-attachments/assets/d87e935e-8ce4-4d8a-b310-fa0e2988be49)

## Installation

Install required modules:

```bash
pip install -r requirements.txt
```

## Notes
- Please comply with relevant laws and regulations when using this tool.
- This tool is for educational and testing purposes only.
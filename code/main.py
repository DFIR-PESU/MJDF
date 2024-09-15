import os
import subprocess
import sqlite3
import time
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget,QDialog, QToolBar, QAction, QScrollArea,QTextEdit
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from threading import Thread
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re
import shutil
import json
import csv
import pandas as pd
import joblib
import numpy as np

# Database setup function
def setup_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS pdf_analysis (
                      id INTEGER PRIMARY KEY,
                      timestamp TEXT NOT NULL,
                      memory_percent REAL NOT NULL,
                      pdf_name TEXT NOT NULL,
                      js_present INTEGER NOT NULL,
                      extracted_js_names TEXT)''')
    conn.commit()
    conn.close()

class ExtractionModule:
    def __init__(self, db_path):
        self.db_path = db_path

    def extract_javascript(self, pdf_file, display_label):
        try:
            output = subprocess.check_output(["pdfextract", pdf_file], stderr=subprocess.STDOUT)
            cmd_output = output.decode("utf-8")
            

            match = re.search(r"Extracted (\d+) scripts to '([^']+)'", cmd_output)
            
            
            if (match):
                num_scripts_extracted = int(match.group(1))
                scripts_path = match.group(2)
                js_present = num_scripts_extracted > 0
                if (js_present and os.path.exists(scripts_path)):
                    js_files = [os.path.join(scripts_path, f) for f in os.listdir(scripts_path) if f.endswith('.js')]
                    js_names = ", ".join(os.path.basename(f) for f in js_files)
                    
                    return js_files  # Return list of .js files
                else:
                    js_names = "No scripts found"
                    
            else:
                js_present = 0
                js_names = "Scripts folder not found"

            # Clear contents of sandbox_dump_after.json and write zeros to CSV if no .js files found
            if (not js_present):
                sandbox_json_path = "/home/remnux/malware-jail/sandbox_dump_after.json"
                log_file_path = "/home/remnux/malware-jail/malware/output.txt"
                with open(sandbox_json_path, 'w') as file:
                    json.dump({}, file)
                with open(log_file_path, 'w') as file:
                    file.write(" ")
                    

                csv_file_path = "/home/remnux/malware-jail/output.csv"
                with open(csv_file_path, 'w', newline='') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow([0] * 8)  # Assuming 8 columns as per the classify_pdf method

            memory_usage = psutil.virtual_memory().percent
            self.save_to_database(pdf_file, memory_usage, js_present, js_names)

        except subprocess.CalledProcessError as e:
            display_label.setText(f"Error running extraction tool: {e}\n")

    def save_to_database(self, pdf_name, memory_percent, js_present, extracted_js_names):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        cursor.execute('''INSERT INTO pdf_analysis (timestamp, memory_percent, pdf_name, js_present, extracted_js_names)
                          VALUES (?, ?, ?, ?, ?)''',
                       (timestamp, memory_percent, pdf_name, js_present, extracted_js_names))
        conn.commit()
        conn.close()

class WatchdogModule(FileSystemEventHandler):
    def __init__(self, display_label, db_path, malware_module):
        self.display_label = display_label
        self.db_path = db_path
        self.observer = None
        self.extraction_module = ExtractionModule(db_path)
        self.malware_module = malware_module  # Pass the malware module instance

    def monitor_directory(self, directory):
        self.observer = Observer()
        self.observer.schedule(self, directory, recursive=False)
        self.observer.start()
        try:
            while self.observer.is_alive():
                self.observer.join(1)
        finally:
            self.observer.stop()
            self.observer.join()

    def on_created(self, event):
        if (not event.is_directory and event.src_path.endswith('.pdf')):
            self.display_label.setText(f"New PDF file detected: {event.src_path}\n")
            js_files = self.extraction_module.extract_javascript(event.src_path, self.display_label)
            if (js_files):
                self.malware_module.process_js_files(js_files, self.display_label)
import subprocess
class MalwareAnalysisModule:
    def __init__(self, malware_jail_dir):
        self.malware_jail_dir = malware_jail_dir

    def process_js_files(self, js_files, display_label):
        try:
            display_label.setText(f"Malware Analysis - Received JS Files: {js_files}\n")
            malware_folder = os.path.join(self.malware_jail_dir, "malware")
            display_label.setText(f"Malware Analysis - Malware Folder: {malware_folder}\n")

            if (not os.path.exists(malware_folder)):
                display_label.setText("Malware Analysis - Creating malware folder...\n")
                os.makedirs(malware_folder)

            for js_file in js_files:
                src_path = js_file
                dest_path = os.path.join(malware_folder, os.path.basename(js_file))
                display_label.setText(f"Malware Analysis - Copying {src_path} to {dest_path}\n")
                shutil.copy2(src_path, dest_path)

                # Run the command for each copied .js file
                command = f"node jailme.js  --down=y malware/{os.path.basename(js_file)} > /home/remnux/malware-jail/malware/output.txt"
                output_file = "/home/remnux/malware-jail/malware/output.txt"
                with open(output_file, 'w') as f:
                	subprocess.run(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
                

                display_label.setText(f"Malware Analysis - Running command: {command}\n")
                command_output = subprocess.check_output(command, shell=True, cwd=self.malware_jail_dir, stderr=subprocess.STDOUT)



        except subprocess.CalledProcessError as e:
            display_label.setText(f"Error running malware analysis: {e.output.decode('utf-8')}\n")

class UIModule(QMainWindow):
    def __init__(self, directory_to_monitor, malware_jail_dir):
        super().__init__()
        self.setWindowTitle("PDF JavaScript Extractor")
        self.setMinimumSize(800, 600)
        self.layout = QVBoxLayout()

        # Initialize UI and theme
        self.init_ui()
        self.apply_light_theme()

        self.directory_to_monitor = directory_to_monitor
        self.db_path = "system_monitor.db"
        setup_database(self.db_path)  # Ensure database is set up
        self.malware_module = MalwareAnalysisModule(malware_jail_dir)
        self.watchdog_module = WatchdogModule(self.display_label, self.db_path, self.malware_module)

    def init_ui(self):
        # Header
        header_layout = QVBoxLayout()
        header_label = QLabel("PDF JavaScript Extractor")
        header_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(header_label)
        self.layout.addLayout(header_layout)

        # Scroll area for displaying content
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.display_label = QLabel()
        self.display_label.setAlignment(Qt.AlignTop)
        self.display_label.setWordWrap(True)
        self.scroll_area.setWidget(self.display_label)
        self.layout.addWidget(self.scroll_area)

        # Buttons layout
        buttons_layout = QVBoxLayout()
        
        self.capture_memory_button = QPushButton("Capture Memory")
        self.capture_memory_button.setIcon(QIcon("dark_mode.jfif"))  # Replace with your icon path
        self.capture_memory_button.clicked.connect(self.capture_memory)
        buttons_layout.addWidget(self.capture_memory_button)


        self.analyse_memory_button = QPushButton("Analyse Memory")
        self.analyse_memory_button.setIcon(QIcon("memory.png"))  # Replace with your icon path
        self.analyse_memory_button.clicked.connect(self.open_analyze_window)
        buttons_layout.addWidget(self.analyse_memory_button)

        self.classify_button = QPushButton("Classify")
        self.classify_button.setIcon(QIcon("classify.png"))  # Replace with your icon path
        self.classify_button.clicked.connect(self.analyze_pdf)
        buttons_layout.addWidget(self.classify_button)

        self.layout.addLayout(buttons_layout)

        # Set central widget
        central_widget = QWidget()
        central_widget.setLayout(self.layout)
        self.setCentralWidget(central_widget)

        # Toolbars
        toolbar = QToolBar()
        self.addToolBar(toolbar)

        start_action = QAction(QIcon("start.png"), "Start", self)  # Replace with your icon path
        start_action.triggered.connect(self.start_monitoring)
        toolbar.addAction(start_action)

        stop_action = QAction(QIcon("stop.png"), "Stop", self)  # Replace with your icon path
        stop_action.triggered.connect(self.stop_monitoring)
        toolbar.addAction(stop_action)

        view_db_action = QAction(QIcon("database.jpg"), "View DB", self)  # Replace with your icon path
        view_db_action.triggered.connect(self.view_database_contents)
        toolbar.addAction(view_db_action)

        clear_action = QAction(QIcon("clear.png"), "Clear", self)  # Replace with your icon path
        clear_action.triggered.connect(self.clear_status)
        toolbar.addAction(clear_action)

    def apply_light_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #007BFF;
                color: white;
                border-radius: 5px;
                padding: 10px 15px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #ccc;
                border-radius: 5px;
                padding: 10px;
            }
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #333;
            }
            QWidget {
                font-family: Arial, sans-serif;
            }
        """)




    def analyze_pdf(self):
      # Path to the log file
      log_file_path = "/home/remnux/malware-jail/malware/output.txt"

      # Words to search for
      search_words = {
         "WScript.Shell": "register_access",
         "document.write": "write_operations",
         "document.writeln": "write_operations",
         "ActiveXObject": "activex_controls",
         "MSXML2.XMLHTTP": "network_activities",
         "FileSystemObject": "directory_file_operations",
         "<iframe": "embedded_iframes",
         "ADODB_Stream": "data_types_handling",
         "Scripting_Dictionary": "data_types_handling",
         "VBScript_RegExp": "data_types_handling"
      }

      # Initialize the feature counts
      features = {
         "data_length": 0,
         "register_access": 0,
         "write_operations": 0,
         "activex_controls": 0,
         "network_activities": 0,
         "directory_file_operations": 0,
         "embedded_iframes": 0,
         "data_types_handling": 0
      }

      # Read the log file
      try:
         with open(log_file_path, 'r') as file:
            log_data = file.readlines()
      except FileNotFoundError:
         log_data = []

      # Calculate data length
      features["data_length"] = sum(len(line) for line in log_data)

      # Search for the words in the log data
      for line in log_data:
         for word, feature in search_words.items():
            if word in line:
               features[feature] = 1

      # Adjust the data_types_handling feature to be binary
      features["data_types_handling"] = int(features["data_types_handling"] > 0)

      # Define the header and the row data
      row = [
         features["data_length"], features["register_access"], features["write_operations"], features["activex_controls"],
         features["network_activities"], features["directory_file_operations"], features["embedded_iframes"], features["data_types_handling"]
      ]

      # Path to the output CSV file
      csv_file_path = "/home/remnux/malware-jail/output.csv"

      # Write the data to a CSV file
      with open(csv_file_path, 'w', newline='') as csvfile:
         csvwriter = csv.writer(csvfile)
         csvwriter.writerow(row)

      self.display_label.setText(f"Data written to {csv_file_path}")

      # Load the new input data
      new_input_path = "/home/remnux/malware-jail/output.csv"
      new_input_df = pd.read_csv(new_input_path, header=None)

      # Load the trained model
      model_path = "/home/remnux/Capstone/random_forest_model.joblib"
      loaded_model = joblib.load(model_path)

      # Predict the label for the new input
      new_input = new_input_df.values.reshape(1, -1)  # Reshape if necessary
      prediction = loaded_model.predict(new_input)

      label_map = {"Malware": "malicious pdf", "Benign": "benign pdf"}
      predicted_label = label_map[prediction[0]]

      self.display_label.setText(predicted_label)


    def capture_memory(self):
       
        command = "sudo ./avml memory.dmp"
        try:
            os.chdir("/home/remnux/Desktop/")
            # Execute the command
            subprocess.run(command, shell=True, check=True)
            self.display_label.setText(f"Memory capture successful\n")
        except subprocess.CalledProcessError as e:
            self.display_label.setText(f"Failed to capture memory: {e}")


    def start_monitoring(self):
        self.monitoring_thread = Thread(target=self.watchdog_module.monitor_directory, args=(self.directory_to_monitor,))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        self.display_label.setText("Monitoring started...\n")

    def stop_monitoring(self):
        if (self.watchdog_module.observer is not None):
            self.watchdog_module.observer.stop()
        if (self.monitoring_thread.is_alive()):
            self.monitoring_thread.join()
        self.display_label.setText("Monitoring stopped...\n")

    def view_database_contents(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''SELECT pdf_name, extracted_js_names FROM pdf_analysis''')
        rows = cursor.fetchall()
        self.display_label.clear()
        for row in rows:
            self.display_label.setText(f"PDF File: {row[0]}, Extracted JS Files: {row[1]}\n")
        conn.close()

    def clear_status(self):
        self.display_label.clear()
    
    def open_analyze_window(self):
        self.analyze_window = AnalyzeWindow(self)
        self.analyze_window.show()
        self.hide()

class AnalyzeWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Analyze Memory")
        self.setGeometry(100, 100, 800, 600)  # Set the window size

        # Set up the layout
        layout = QVBoxLayout()

        # Dictionary of command plugins
        self.commands = {
            1: "linux_pslist",
            2: "linux_bash",
            3: "linux_netstat",
            4: "linux_lsmod",
            5: "linux_check_afinfo",
            6: "linux_dmesg",
            7: "linux_lsof",
            8: "linux_malfind",
            9: "linux_proc_maps",
            10: "linux_psaux",
            11: "linux_check_creds"
        }

        # Add buttons for analysis commands
        self.buttons = []
        for i in range(1, 12):
            plugin_name = self.commands[i]
            button = QPushButton(plugin_name)
            button.clicked.connect(lambda _, x=i: self.run_command(x))
            layout.addWidget(button)
            self.buttons.append(button)

        # Add a text area to display command output
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        # Add a back button
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)

        self.setLayout(layout)

    def run_command(self, command_number):
        command = self.commands.get(command_number, "")
        if command:
            self.analyse_memory(command)
            

            
    def analyse_memory(self, plugin):
        try:
            # Navigate to the directory
            os.chdir("/home/remnux/volatility/")
           
            # Command to execute Python 2.7 script with the specified plugin
            command = f"python2.7 vol.py -f /home/remnux/Desktop/memory.dmp --profile=LinuxUbuntu-5_4_0-122-genericx64 {plugin} | more"
           
            # Execute command and capture output
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
           
            # Display output in QTextEdit
            self.output_area.append(f"Analyse Memory - Command Output ({plugin}):\n{output.decode('utf-8')}\n")
           
        except subprocess.CalledProcessError as e:
            self.output_area.append(f"Error running memory analysis ({plugin}): {e.output.decode('utf-8')}\n")
        except Exception as ex:
            self.output_area.append(f"Exception occurred ({plugin}): {str(ex)}\n")


    def go_back(self):
        self.parent().show()
        self.close()

if __name__ == "__main__":
    app = QApplication([])
    directory_to_monitor = os.path.expanduser("~/Downloads")
    malware_jail_dir = "/home/remnux/malware-jail"  # Update with actual path
    ui = UIModule(directory_to_monitor, malware_jail_dir)
    ui.show()
    app.exec_()


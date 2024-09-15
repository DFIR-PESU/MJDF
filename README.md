
# Capstone Project: An approach to detect malicious JavaScript (fileless/filebased) malware 

This project focuses on detecting fileless malware embedded in PDFs using static and dynamic analysis techniques, memory forensics, and machine learning. The system monitors downloaded PDFs, extracts JavaScript, and uses machine learning to classify whether the PDF contains malicious content. If needed, memory forensics tools are utilized to detect fileless malware.

## Objective

The goal of this project is to detect fileless malware embedded in PDFs by analyzing the JavaScript within the files and using memory forensics to identify malicious behavior that resides only in memory.

## Project Components

1. **PDF Monitoring and Extraction**: The system monitors for new PDF files in the `Downloads` directory and extracts JavaScript code using the Origami `pdfextract` tool.
2. **Dynamic Analysis**: Executes JavaScript in a sandbox environment to observe its behavior and determine whether it’s malicious.
3. **Machine Learning**: A Random Forest classifier is used to determine if the JavaScript embedded in the PDF is malicious.
4. **Memory Forensics**: Utilizes AVML  for memory capture and Volatility for analyzing memory dumps to detect fileless malware.


## Technology Stack

- **Frontend**: PyQt5 (for the user interface)
- **Backend**: Python(handling extraction, analysis, and memory forensics)
- **PDF Analysis**: Origami framework with `pdfextract`
- **JavaScript Analysis**: Malware-jail sandbox for dynamic analysis
- **Machine Learning**: scikit-learn for classification using Random Forest
- **Memory Forensics**: Volatility, AVML, for memory capturing and analysis


## Installation and Setup

### Prerequisites

- Python 3.8.x >=10 and Python 2.7
- Volatility (for memory analysis)
- pdfextract (from Origami framework)
- Watchdog (for monitoring files)
- Node.js (for Malware-jail sandbox)
  
  ### Virtual Machine and REMnux Setup

1. **Install VirtualBox (Version 7.0.10)**:
   - Download and install [VirtualBox 7.0.10](https://www.virtualbox.org/wiki/Download_Old_Builds_7_0).

2. **Download REMnux VM**:
   - REMnux is based on Ubuntu 20.04 (x86/amd64). Download the REMnux OVA from [REMnux Official Site](https://docs.remnux.org/install-distro/get-virtual-appliance).

3. **Set Up REMnux VM**:
   - Import the REMnux OVA or create a new VM in VirtualBox, specifying Ubuntu 20.04 as the OS type.
   - Allocate necessary resources (RAM, CPU, storage) as required by REMnux.

4. **Install Required Tools**:
   - Use REMnux’s pre-installed tools for malware analysis or install additional ones:
   - Install Watchdog for monitoring PDF downloads:
     ```bash
     pip install watchdog
     ```
   - Install Origami gem version 2.1.0 for extracting JavaScript from PDF files:
     ```bash
     sudo apt-get install ruby
     gem install origami --version 2.1.0
     ```

5. **Install Python Versions**:
   - Ensure both Python 3.8.10 and Python 2.7 are installed in the VM to support various tools and frameworks:
     ```bash
     sudo apt-get install python3.8 python2.7
     ```
   - Set up virtual environments to handle both Python versions if needed:
     ```bash
     python3.8 -m venv venv_py38
     source venv_py38/bin/activate
     ```

6. **Install Machine Learning Libraries**:
   - In Python 3.8.10, install `scikit-learn` and other required libraries for the Random Forest classifier:
     ```bash
     pip install scikit-learn pandas numpy
     ```

### Clone the Repository

```bash
git clone https://github.com/DFIR-PESU/Malicious_JavaScript_Detector_Fileless_Filebased-.git
cd malicious_javascript_detector-fileless
```

### Install Dependencies


 **Install Malware-jail sandbox** from GitHub:
   ```bash
   git clone https://github.com/HynekPetrak/malware-jail.git
   cd malware-jail
   npm install
   ```


### Set Up Memory Forensics

#### Microsoft AVML

1. **Download and Run AVML to Create Memory Capture**:
   - Clone the AVML repository:
     ```bash
     git clone https://github.com/microsoft/avml.git
     cd avml
     ```
   - Run AVML to create a memory capture:
     ```bash
     sudo ./avml memory.dmp
     ```

#### Build a Custom Volatility Profile

1. **Clone Volatility**:
   ```bash
   git clone https://github.com/volatilityfoundation/volatility.git
   python2.7 setup.py install
   
   ```

2. **Generate the Volatility Profile**:

   - Navigate to the Volatility tools directory:
     ```bash
     cd ./volatility/tools/linux
     ```

   - Install `dwarfdump`:
     ```bash
     sudo apt install dwarfdump
     ```

   - Build the profile:
     ```bash
     make
     ```

   - Check your current Linux kernel version:
     ```bash
     uname -a
     ```

   - Create a `.zip` file for the custom profile:
     ```bash
     sudo zip [DISTRO_KERNEL].zip ./tools/linux/module.dwarf /boot/System.map-[KERNEL_VERSION]
     ```

3. **Install the Custom Volatility Profile**:

   Move the `.zip` file to the appropriate Volatility directory:
   ```bash
   mv [DISTRO_KERNEL].zip ./volatility/plugins/overlays/linux
   ```

#### Run Volatility with the Custom Profile(just to verify)

1. **Verify if the Custom Profile is Available**:
   ```bash
   ./vol.py --info | more
   ```

2. **Analyze the Memory Capture with the Custom Profile**:
   ```bash
   ./vol.py -f /path/to/memory.dmp --profile=[NEW_PROFILE_NAME] [PLUGIN]
   ```

## Project Structure

The project is organized into the following directories and files:

```
Capstone/
│
├── code/
│   ├── classify.png           # Image file for classification feature
│   ├── classify.webp          # WebP version of classification image
│   ├── clear.png              # Image file for clear button
│   ├── database.jpg           # Image file for database representation
│   ├── main.py                # Main Python script to run the project
│   ├── memory.png             # Image file for memory feature
│   ├── start.jpeg             # JPEG image for the start button
│   ├── start.png              # PNG image for the start button
│   ├── stop.png               # Image file for stop button
│
├── dataset/
│   ├── combined_dataset.csv   # CSV file with the combined dataset used for training
│   ├── random_forest_model.joblib  # Serialized Random Forest model
│   └── train_model.py         # Python script to train the model
```
## Usage

1. **Start the PyQt5 application**:
   ```bash
   python3 main.py
   ```

2. **PDF Monitoring**:
   - The system will automatically monitor the `Downloads` directory for PDF files.
   - Extract JavaScript from the PDF, run dynamic analysis using the Malware-jail sandbox, and classify it as malicious or benign.

3. **Memory Analysis**:
   - If a file is classified as malicious, use Volatility to analyze the system’s memory for checking signs of fileless malware.

## Features

- **PDF Monitoring**: Automatically monitors for new PDF downloads and extracts JavaScript.
- **JavaScript Analysis**: Uses a sandbox environment to analyze JavaScript embedded in PDFs.
- **Machine Learning Classification**: Utilizes a Random Forest classifier to determine if the JavaScript is malicious.
- **Memory Forensics**: Captures and analyzes memory to detect fileless malware.

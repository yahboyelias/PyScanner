# PyScanner
Python - Network Scanner

```markdown
# Network Scanner

A Python script for scanning networks to discover live hosts and open ports.

## Features

- Scan for live hosts on a specified IP range.
- Scan for open ports on live hosts.
- Perform service detection on open ports.
- GUI mode for user-friendly interaction.
- Export scan results to a CSV file.

## Installation

### Windows

1. **Install Python**: If you don't have Python installed, download and install it from the official Python website: [Python Downloads](https://www.python.org/downloads/).

2. **Open Command Prompt**: Open the Command Prompt by searching for "cmd" or "Command Prompt" in the Start menu.

3. **Install Required Libraries**: Run the following command to install the required libraries:

   ```bash
   pip install scapy
   ```

   This will install the `scapy` library.

4. **Clone the Repository**: You can download or clone the Network Scanner repository from GitHub to your local machine.

   ```bash
   git clone https://github.com/your-username/network-scanner.git
   cd network-scanner
   ```

5. **Run the Network Scanner**:

   ```bash
   python pyscanner.py --target-ip <target_ip_range> --output-csv <output_csv_filename>
   ```

   To run the GUI mode, use:

   ```bash
   python pyscanner.py --gui
   ```

### macOS

1. **Install Python**: macOS typically comes with Python preinstalled. Open the Terminal app, and you can verify your Python version by running:

   ```bash
   python --version
   ```

   If you need to update Python, consider using a package manager like Homebrew to install Python 3:

   ```bash
   brew install python@3
   ```

2. **Install Required Libraries**: Run the following command to install the required libraries:

   ```bash
   pip3 install scapy
   ```

   This will install the `scapy` library.

3. **Clone the Repository**: You can download or clone the Network Scanner repository from GitHub to your local machine.

   ```bash
   git clone https://github.com/your-username/network-scanner.git
   cd network-scanner
   ```

4. **Run the Network Scanner**:

   ```bash
   python3 pyscanner.py --target-ip <target_ip_range> --output-csv <output_csv_filename>
   ```

   To run the GUI mode, use:

   ```bash
   python3 pyscanner.py --gui
   ```

### Linux (Ubuntu/Debian)

1. **Install Python**: Most Linux distributions come with Python preinstalled. You can verify your Python version by running:

   ```bash
   python --version
   ```

   If needed, you can install Python 3 with:

   ```bash
   sudo apt-get install python3
   ```

2. **Install Required Libraries**: Run the following command to install the required libraries:

   ```bash
   pip3 install scapy
   ```

   This will install the `scapy` library.

3. **Clone the Repository**: You can download or clone the Network Scanner repository from GitHub to your local machine.

   ```bash
   git clone https://github.com/your-username/network-scanner.git
   cd network-scanner
   ```

4. **Run the Network Scanner**:

   ```bash
   python3 pyscanner.py --target-ip <target_ip_range> --output-csv <output_csv_filename>
   ```

   To run the GUI mode, use:

   ```bash
   python3 pyscanner.py --gui
   ```

## Usage

- To scan for live hosts on an IP range and save the results to a CSV file:

  ```bash
  python pyscanner.py --target-ip <target_ip_range> --output-csv <output_csv_filename>
  ```

- To run the GUI mode:

  ```bash
  python pyscanner.py --gui
  ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```

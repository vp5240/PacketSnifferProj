
# **Network Packet Sniffer**

Welcome to the **Network Packet Sniffer** project! This Python-based application is designed to capture, analyze, and display network traffic in real time. Built using PyShark and Tkinter, it combines functionality and simplicity to help you learn and explore networking concepts while providing practical tools for analysis.

---

## **Features**
This packet sniffer includes:
- **Real-Time Packet Capture**: Monitor live traffic on any network interface.
- **File Import**: Analyze previously saved packet capture files like `.pcap`, `.pcapng`, and `.cap`.
- **Dynamic Filtering**: Focus on specific packets based on protocol (TCP, UDP, ICMP) or IP addresses.
- **Detailed Analysis**: Dive into packet details with a user-friendly interface, including protocols, IPs, and payloads.
- **Traffic Statistics**: Visualize live packet counts and traffic rates by protocol.

---

## **Project Structure**
- **`app.py`**: The main Python script, housing both the GUI and packet handling logic.
- **`requirements.txt`**: A list of all dependencies to set up your environment easily.
- **GUI Components**:
  - **Packet Table**: View captured packets in real-time.
  - **Details Panel**: Drill down into individual packet information.
  - **Filters Panel**: Apply real-time filters to refine your view.
  - **Menu Options**: Import packet files and access additional features.

---

## **How to Use**
### Running the Application
1. Navigate to the project folder.
2. Launch the application:
   ```bash
   python app.py
   ```

3. Start capturing live traffic or load a saved capture file via the **File > Import .pcap** menu.
4. Apply filters to narrow down results or select a packet for detailed analysis.

---

## **Installation Guide**
### Prerequisites
- **Python 3.7 or newer**.
- **TShark (Wireshark CLI)**: Used for live packet capturing.

### Installation Steps

#### **On Linux (e.g., Arch Linux):**
1. Install Python and Tkinter:
   ```bash
   sudo pacman -S python python-tk
   ```
2. Install TShark:
   ```bash
   sudo pacman -S wireshark-cli
   ```
3. Add your user to the `wireshark` group for permissions:
   ```bash
   sudo usermod -aG wireshark $USER
   ```
4. Activate the virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

#### **On Windows:**
1. Install Python and ensure `Add Python to PATH` is selected during installation.
2. Download Wireshark and include the **TShark** component.
3. Set up the virtual environment:
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```

---

## **Configuration**
Before running the application, you need to set the correct network interface for live packet capture.

1. **Edit the Network Interface**:
   - Open the `app.py` file in a text editor.
   - Navigate to **line 25**, which contains the following code:
     ```python
     self.interface = "wlp2s0"  # Default interface - Change as per your system
     ```
   - Replace `"wlp2s0"` with the name of your network interface.

2. **Find Your Network Interface**:
   - **On Windows**:
     1. Open Command Prompt and type:
        ```cmd
        ipconfig
        ```
     2. Look for the **Ethernet adapter** or **Wi-Fi** section. The network interface name will typically be `Ethernet` or `Wi-Fi`.
   - **On Linux (e.g., Arch Linux)**:
     1. Open a terminal and type:
        ```bash
        ip addr
        ```
     2. Look for an interface with a valid IP address. Common examples include `wlp2s0`, `eth0`, or `enp0s3`.
     3. Use the detected interface name (e.g., `wlp2s0`) and replace the default value in the `app.py` file.

---

## **Troubleshooting**
1. **Permission Errors (Linux)**:
   - Add your user to the `wireshark` group and log out/in:
     ```bash
     sudo usermod -aG wireshark $USER
     ```

2. **Tkinter or Display Errors**:
   - Install `python-tk` and fix display settings:
     ```bash
     sudo pacman -S python-tk
     xhost +si:localuser:$(whoami)
     ```

3. **Running as Root**:
   - If needed, allow root access to the display:
     ```bash
     sudo xhost +local:
     sudo python app.py
     ```

---

## **Testing Results**
### Functionality Tests
- **Real-Time Packet Capture**: Successfully captured and displayed packets across multiple environments.
- **Filtering**: Verified protocol and IP-based filtering with dynamic updates.
- **Offline Analysis**: Imported `.pcap` files and displayed packet details accurately.
- **Statistics**: Matched packet counts and traffic rates to expected values.

### Performance
- **High Traffic**: Handled alot of packets per second.
- **Resource Usage**: The application was easly handled with minimal memory usage and low CPU demand.

---





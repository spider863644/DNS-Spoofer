# DNS-Spoofer

DNS-Spoofer is a Python-based tool for performing DNS spoofing attacks. It manipulates DNS responses to redirect a victim's internet traffic. Instead of resolving a domain to its legitimate IP address, the tool responds with a fake IP, leading users to attacker-controlled sites.

## 🚀 Features

1. Real-Time DNS Spoofing: Intercept and manipulate DNS queries in real time.

2. Targeted Redirection: Redirect specific domains to specified IP addresses.

3. Dynamic Domain Resolution: Automatically resolves target domains to IPs.

4. Simple CLI Interface: Easy setup and execution for penetration testing.




## 📋 Prerequisites

1. Linux operating system

2. Python 3.x

3. Scapy library (install using pip3 install scapy)

4. Root privileges to capture and manipulate network traffic


## ⚠️ Important

Same Network: You must be on the same network as the target for this tool to work.

Educational Use Only: This tool is designed for ethical hacking and security testing. Use it responsibly.


## 🛠 Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/DNS-Spoofer.git
cd DNS-Spoofer
```

## 2. Install dependencies:
```
pip install scapy
pip install colorama
pip install requests
```

## 🔧 Usage
```
sudo python3 dns.py -m domain1.com:target_ip domain2.com:target_ip
```
### Example:
```
sudo python3 dns.py -m example.com:192.168.1.100 victim.com:10.0.0.1
```


## 👨‍💻 Author

Spider Anongreyhat<br>
Team: TermuxHackz Society<br>
GitHub: spider863644


## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only. Unauthorized use is illegal and unethical.





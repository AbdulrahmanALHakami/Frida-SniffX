# Frida-SniffX
![Frida](https://img.shields.io/badge/Frida-16.5.6-blue) 
![iOS](https://img.shields.io/badge/iOS-Jailbreak%20Bypass-green)
![Security](https://img.shields.io/badge/Security-Bypass-red)

SniffX is a Frida-based network traffic inhaler designed to intercept and enrol network connections from iOS apps. It allows security researchers and penetration testing to analyse network activity, including encrypted SSL/TLS traffic


Attaches to running iOS applications using Frida.

Hooks network-related functions like:

NSURLSession

NSURLConnection

CFNetwork

SSL_write

SSL_read

send

Logs intercepted data to /tmp/sniffed_data.log.

Supports hooking Objective-C and C functions.

Intercept HTTP/HTTPS Requests & Responses (including NSURLSession, CFNetwork, SSL_write, SSL_read)

Bypass SSL Pinning automatically.

Make sure you have Frida installed on your system:
pip install frida


git clone https://github.com/your-repo/SniffX.git
cd SniffX

Run SniffX with an iOS app name or a PID:
python3 SniffX.py <app_name_or_PID>




The script attaches to the specified app via Frida.

Hooks network-related APIs.

Captures and logs network traffic, including encrypted data sent via SSL



This tool is intended for security research and penetration testing only. Unauthorized usage against third-party applications may violate legal and ethical guidelines.


Feel free to submit issues, suggestions, or pull requests to improve SniffX! 



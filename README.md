# Frida-SniffX

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





The script attaches to the specified app via Frida.

Hooks network-related APIs.

Captures and logs network traffic, including encrypted data sent via SSL



This tool is intended for security research and penetration testing only. Unauthorized usage against third-party applications may violate legal and ethical guidelines.


Feel free to submit issues, suggestions, or pull requests to improve SniffX! 



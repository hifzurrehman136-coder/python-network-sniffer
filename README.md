
# Python Network Sniffer (Raw Socket Implementation)

This project is a **Python-based Network Sniffer** that captures and analyzes network packets using raw sockets. It inspects incoming IPv4 packets and extracts detailed information about ICMP, TCP, and UDP protocols.

The main goal of this project is to demonstrate how packet sniffing works at a low level and to provide hands-on experience with network protocol analysis and cybersecurity fundamentals.

⚠️ **Disclaimer:**
This project is strictly for educational purposes and should only be used in a controlled lab environment or on your own network. Unauthorized packet sniffing on networks without permission is illegal and unethical.

---

## How It Works

* The program creates a **raw socket** using the `socket` module.
* It captures all incoming IPv4 packets.
* Extracts important header information such as:

  * IP Version
  * Header Length
  * TTL (Time To Live)
  * Protocol Type
  * Source IP
  * Destination IP
* Based on the protocol type, it further analyzes:

    ICMP packets
    TCP segments
    UDP segments
  The payload data is formatted and displayed in a readable multi-line structure.

 Features

* Real-time packet capturing
* IPv4 header analysis
* ICMP packet inspection
* TCP segment analysis (flags, sequence, acknowledgment numbers)
* UDP segment analysis
* Hex-formatted payload display
* Structured and readable console output

---

Technologies Used

* Python 3
* socket module (Raw Sockets)
* struct module (Binary data unpacking)
* textwrap module (Formatted output)

---

 Learning Objectives

By working on this project, you will understand:

* How raw sockets operate
* Structure of IPv4 packets
* TCP, UDP, and ICMP protocol headers
* Bitwise operations for flag extraction
* Binary data unpacking using `struct`
* Basic network traffic analysis

---

 Requirements

⚠️ Must run with **Administrator privileges** (especially on Windows).

Run the script:

python network_sniffer.py


 Future Improvements

* Add packet filtering (e.g., filter by port or protocol)
* Save captured packets to a file
* Add GUI interface
* Add Ethernet frame parsing
* Implement packet statistics summary


Educational Value

This project is ideal for students learning:

* Computer Networks
* Cybersecurity
* Ethical Hacking
* Network Protocol Analysis


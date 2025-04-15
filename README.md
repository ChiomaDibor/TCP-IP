# A Simple Guide to Isolating Network Traffic with TCPDump for SOC Analysts

## Objective

1. To demonstrate practical use of TCPDump filters to analyze packet capture (pcap) files, focusing on filtering by host, port, protocol, and network range.
2. To extract meaningful insights from packet payloads using ASCII and hex decoding for deeper threat detection.

## Skills Learned

- Proficiency in applying TCPDump filters (host, port, protocol, network range) to isolate relevant traffic.
- Ability to analyze captured packets, inspecting IPs, ports, sequence numbers, and flags.
- Using the -A and -X flags to decode and view packet payloads in both ASCII and hex format, which is crucial for detecting suspicious content and anomalies.
- Capability to detect suspicious activities, such as unusual PowerShell traffic or signs of malware.
- Enhanced incident response through targeted filtering to identify potential threats faster.
- Competence in working with pcap files for detailed network traffic analysis.


## Tools Used

- TCPDump: For capturing and analyzing network traffic from pcap files.
- Kali Linux: As the operating system for running TCPDump and performing network traffic analysis.

## Steps
#### Task 1: Getting started with TCPDUMP
Go to your Kali Linux Terminal and switch to the root shell. 
To do this, type in

`sudo su-`


<br>

#### Task 2: Set up your environment

Navigate to the directory containing the pcap file.
<br>

![image](https://github.com/user-attachments/assets/4bd83526-65fe-47ac-9040-f60f81430b37)

*For this lab, a pcap file magnitude_1hr.pcap has already been downloaded into my lab environment and stored in the /opt/tcpdump directory.*


<br>

#### Task 3: Analyzing the Pcap file
1. Checking Network Traffic from a Specific Host:
`
tcpdump -n -r /opt/tcpdump/magnitude_1hr.pcap host 192.168.99.52`

*-n prevents hostname resolution(display IP addresses instead of hostname) while -r reads the data from the pcap file*

This command filters traffic involving the IP 192.168.99.25. You can see the source IP address + port, destination IP address + port, bit flag, sequence number, and data size.
<br>

![image](https://github.com/user-attachments/assets/e9a09e4c-2466-45c7-8f80-215d3a40edd0)

<br>

2. Filtering by Port Number

This command filters only HTTP traffic (port 80) related to the host:

`tcpdump -n -r /opt/tcpdump/magnitude_1hr.pcap host 192.168.99.52 and port 80`

You can see from the screenshot below, it is showing us all HTTP(port 80) traffic received and sent on that IP address.
<br>

![image](https://github.com/user-attachments/assets/f8a1b349-86c8-4b8b-b55b-56afcba77b95)

<br>

3. Viewing ASCII Data in Packets

Getting the metadata from the packets is nice. Using this command, we can get the full ASCII decode of the packet and the payload of the packet:

`tcpdump -n -r /opt/tcpdump/magnitude_1hr.pcap host 192.168.99.52 and port 80 -A`
-A: Displays the packet’s payload in ASCII.
<br>

![image](https://github.com/user-attachments/assets/dbe8eba0-f7a0-47b0-8161-d2716842f01d)

*The HTTP GET requests and actual responses are shown.*
I use | less to prevent unending output and allow me to scroll through one page at a time.
<br>

4. Detecting Suspicious PowerShell Activity
`
tcpdump -n -r /opt/tcpdump/magnitude_1hr.pcap host 192.168.99.52 and port 80 -AX`

*-X: Displays packet data in both hex and ASCII.*
<br>

![image](https://github.com/user-attachments/assets/5dfcf437-3fa6-4123-9cd5-d8680437794b)


The implication of running this command is that we get to see a comprehensive view of the data. During an investigation, hex can help spot unusual byte patterns, while ASCII will help decode and understand the hidden content.

<br>

5. Filtering by Network Range

`tcpdump -n -r /opt/tcpdump/magnitude_1hr.pcap net 192.168.99.0/24`
<br>

![image](https://github.com/user-attachments/assets/82da3365-cae7-4f62-9b9a-8fbdfc6d5919)

This filter will help us to focus on that particular subnet. Very useful when you are seeing traffic either to or from a range of IP addresses.

<br>

6. Filtering by Protocol

To filter by protocol use the IP, TCP, UDP, or other protocol keywords. Here, I am filtering through the IP protocol.

`tcpdump -n -r magnitude_1hr.pcap ip6`
<br>

![image](https://github.com/user-attachments/assets/c6561288-c602-42e5-9104-adce17d11a63)


# Conclusion
Mastering tcpdump takes practice, but it is a must-have skill for SOC Analysts. By leveraging these filters, you can effectively monitor and secure your network, investigate incidents, and ultimately ensure a robust defense against potential threats.

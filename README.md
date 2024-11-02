# ARP-Packet-Capture-and-Analysis
Performs byte-level programming to read each byte and convert it to the ARP header element.
Program Logic:
My program first opens my PCAP file and unpacks it into data. I then check if the data is an actual response 
and request by filtering out the broadcasts with my if statements. After I find my request I store the data into
variables and print them. A boolean variable is then set to true since I got my request. Then I check for my response
and print it. If my response is printed it breaks the loop and ends the code.
How to run code:
To run the code replace "my_arp.pcap" in "f = open('my_arp.pcap','rb')" with the desired file
name. Then press run.

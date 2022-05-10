import csv

rulesFile = "firewall_rules.csv"  # firewall filtering rules
inputFile = "packet_input.txt"  # input contains packets
outputFile = "accept_packet_output.txt"  # output pass packets


def writeToDictionary(packet):
    # write necessary details in ip datagram into data structure
    pktDetails = {}
    pktDetails["protocol"] = packet[69:71]  # TCP = 06  UDP = 11
    pktDetails["source address"] = packet[78:89]
    pktDetails["destination address"] = packet[90:101]
    pktDetails["source port"] = packet[102:107]
    pktDetails["destination port"] = packet[108:113]
    if pktDetails["protocol"] == "06":
        pktDetails["flag"] = packet[141:143]  # ACK set = 10 SYN = 02
    return pktDetails


def rejectPacket(index):
    print(f"Packet {index} rejected by the firewall")


def passPacket(outputInterface, datagram, index):
    with open(outputInterface, "a+") as outputFile:
        outputFile.seek(0)
        outputFile.write(datagram)
    print(f"Packet {index} accepted by the firewall")


def conditionFilter(datagram, rule):
    return (
        (
            datagram["source address"] == rule["Source address"]
            or rule["Source address"] == "Any"
        )
        and (
            datagram["destination address"] == rule["Destination address"]
            or rule["Destination address"] == "Any"
        )
        and (
            datagram["source port"] == rule["Source port"]
            or rule["Source port"] == "Any"
        )
        and (
            datagram["destination port"] == rule["Destination port"]
            or rule["Destination port"] == "Any"
        )
        and (
            datagram["protocol"] == "11"  # UDP
            or (
                datagram["protocol"] == "06"  # TCP need to check flag
                and (datagram["flag"] == rule["ACK"] or rule["ACK"] == "Any")
            )
        )
    )


def firewall(packet, index):
    # get datagram from packet
    datagram = writeToDictionary(packet)
    with open(rulesFile, mode="r") as file:

        csvFile = csv.DictReader(file)  # read firewall filtering rules
        flag = False
        for row in csvFile:
            if flag == True:
                break
            if (
                datagram["protocol"] == "11" or datagram["protocol"] == "06"
            ):  # Filtering for UDP and TCP
                if conditionFilter(datagram, row):
                    flag = True
                    if row["Action"] == "Deny":
                        rejectPacket(index)
                        continue
                    elif row["Action"] == "Allow":
                        passPacket(outputFile, packet, index)
                        continue
        if flag == False:
            passPacket(outputFile, packet, index)


index = 0
with open(inputFile) as inputFile:
    for datagram in inputFile:
        index += 1
        firewall(datagram, index)

import re
import pandas as pd
import numpy as np
import csv



version = 1.1


def process_input(input_file):
    data = {}
    with open(input_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            cipher = row['Cipher']
            api = row['API']
            packet_size = int(row['Packet Size'])
            throughput = int(row['Throughput(Mbps)'])
            if api == 'Traditional':
                continue
            if cipher ==  'Traditional' or cipher == 'Data_Plane':
                 continue

            key = (cipher, api)
            if key not in data:
                data[key] = {'packet_sizes': [], 'throughputs': []}
            data[key]['packet_sizes'].append(packet_size)
            data[key]['throughputs'].append(throughput)
    return data

def write_output(output_file, data):
    with open(output_file, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for key, value in data.items():
            cipher, api = key
            # if api == 'Traditional':
            #     continue
            # if cipher ==  'Traditional' or cipher == 'Data_Plane':
            #     continue

            writer.writerow([cipher, api])
            writer.writerow(value['packet_sizes'])
            writer.writerow(value['throughputs'])
            writer.writerow(" ")


def output_file(input_file, output_file):
    data = process_input(input_file)
    write_output(output_file, data)



def compression(input_file):
    with open(input_file, 'r') as infile:
        # Open the output CSV file for writing
        with open('output.csv', 'w', newline='') as outfile:
            # Define the CSV writer
            writer = csv.writer(outfile)

            writer.writerow(['API', 'Session State', 'Huffman Type', 'Packet Size', 'Compression Level', 'Throughput(Mbps)', 'Compression Ratio'])
            api = ""
            Session_State =""
            Huffman_Type =""
            packet_size = ""
            Compression_Level = ""
            throughput = ""
            Compression_Ratio=""
            x = []
            count = 0
            countB = 0

            for line in infile:
                if count < 2:
                    if count != 1:
                        if line.startswith("API"):
                            api = re.split('\s{2,}', line)[1].strip()
                            if api == 'Data_Plane':
                                count += 1
                            else:
                                api = None  # Reset API if it's not 'Data_Plane'

                    elif api == 'Data_Plane':
                        if line.startswith('Session State') and 'STATELESS' in line:
                            Session_State = re.split('\s{2,}', line)[1].strip()
                            count += 1


                if count == 2:


                    if line.startswith('Huffman'):
                        Huffman_Type = re.split('\s{2,}', line)[1].strip()
                        x.append(api)
                        x.append(Session_State)
                        x.append(Huffman_Type)
                        countB += 1

                    if line.startswith('Direction'):
                        Direction  = re.split('\s{2,}', line)[1].strip()
                        x.append(Direction)
                        countB += 1


                    if line.startswith('Compression Level'):
                        api = re.split('\s{2,}', line)[1].strip()
                        x.append(api)
                        countB += 1

                    if line.startswith('Packet Size'):
                        api = re.split('\s{2,}', line)[1].strip()
                        x.append(api)
                        countB += 1


                    if line.startswith('Throughput(Mbps)'):
                        api = re.split('\s{2,}', line)[1].strip()
                        x.append(api)
                        countB += 1

                    if line.startswith('Compression Ratio'):
                        api = re.split('\s{2,}', line)[1].strip()
                        x.append(api)
                        countB += 1

                    if countB == 6:
                        count = 0
                        countB = 0
                        api = ""
                        Session_State = ""
                        Huffman_Type = ""
                        packet_size = ""
                        Compression_Level = ""
                        throughput = ""
                        Compression_Ratio = ""

    # Split input data into chunks of 8
    chunks = [x[i:i + 8] for i in range(0, len(x), 8)]



    # Append input data to existing CSV file
    with open("result.csv", 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['API', 'Session State', 'Huffman Type', 'Direction', 'Packet Size',
                             'Compression Level', 'Throughput(Mbps)', 'Compression Ratio'])
        for chunk in chunks:
            writer.writerow(chunk)




def log_parser(input_file):
    # Open the input file for reading
    with open(input_file, 'r') as infile:
        # Open the output CSV file for writing
        with open('output.csv', 'w', newline='') as outfile:
            # Define the CSV writer
            writer = csv.writer(outfile)

            # Write the header row to the CSV file
            writer.writerow(['Cipher', 'API', 'Packet Size', 'Throughput(Mbps)'])

            # Initialize variables to store the extracted values

            api = ""
            packet_size =""
            throughput = ""
            x = []
            count = 0
            for line in infile:



                line = line.strip()

                if line.startswith("ECDSA VERIFY"):
                    x.append("ECDSA VERIFY")
                    x.append("NO_API")
                    count += 2


                elif line.startswith("RSA CRT DECRYPT"):
                    x.append("RSA CRT DECRYPT")
                    x.append("NO_API")
                    count += 2

                elif line.startswith("Cipher") or line.startswith("Algorithm Chaining -"):
                    if line.startswith("Cipher"):
                        cipher = line.split(" ")[1]

                    if line.startswith("Algorithm Chaining -"):
                        #pattern = line.split()
                        extracted_value =[]

                        value = line.split(" ")[3:]
                        cipher = ''.join(value)


                    x.append(cipher)
                    count += 1

                elif line.startswith("Algorithm"):
                    api = re.split('\s{2,}', line)[1].strip()
                    x.append(api)
                    count += 1

                elif line.startswith("API"):
                    api = re.split('\s{2,}', line)[1].strip()
                    x.append(api)
                    count += 1
                elif line.startswith("Packet Size") or line.startswith("Packet Mix") or line.startswith("Modulus Size") or line.startswith("EC Size"):
                    if line.startswith("Packet Size"):
                        packet_size = int(re.search(r'Packet Size\s+(\d+)', line).group(1))
                    elif line.startswith("Packet Mix"):
                        packet_size = int(re.search(r'Packet Mix\s+(\d+)', line).group(1))
                    elif line.startswith("Modulus Size"):
                        packet_size = int(re.search(r'Modulus Size\s+(\d+)', line).group(1))
                    elif line.startswith("EC Size"):
                        packet_size = int(re.search(r'EC Size\s+(\d+)', line).group(1))


                    x.append(packet_size)
                    count += 1
                elif line.startswith("Throughput(Mbps)") or line.startswith("Operations per second"):
                    throughput = re.split('\s{2,}', line)[1].strip()
                    x.append(throughput)
                    count += 1
                # print(x)
                if count == 4:
                      count =0
                      writer.writerow(x)
                      x = []
                      api = "N/A"
                      packet_size ="N/A"
                      throughput = "N/A"
                      cipher = "N/A"


if __name__ == '__main__':
    input_file = '2xLBTL_v2.txt'
    print(f"LBTL_LOG version:{version}")
    log_parser(input_file)
    output_file("output.csv", 'result.csv')
    compression(input_file)
    print("result.csv file was created")



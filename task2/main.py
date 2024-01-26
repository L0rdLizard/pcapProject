import csv

def read_csv(file_path):
    data = []
    with open(file_path, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)
        for row in csv_reader:
            data.append(row)
    return data

def process_data(input_data):
    ip_data = {}

    for row in input_data:
        source_ip, source_port, dest_ip, dest_port, received_packets, received_bytes = row[:6]


        if source_ip not in ip_data:
            ip_data[source_ip] = {'received_packets': 0, 'received_bytes': 0, 'sent_packets': 0, 'sent_bytes': 0}

        ip_data[source_ip]['sent_packets'] += int(received_packets)
        ip_data[source_ip]['sent_bytes'] += int(received_bytes)

    
        if dest_ip not in ip_data:
            ip_data[dest_ip] = {'received_packets': 0, 'received_bytes': 0, 'sent_packets': 0, 'sent_bytes': 0}

        ip_data[dest_ip]['received_packets'] += int(received_packets)
        ip_data[dest_ip]['received_bytes'] += int(received_bytes)

    return ip_data

def write_csv(output_data, output_file):
    with open(output_file, 'w', newline='') as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow(['IP', 'Received Packets', 'Received Bytes', 'Sent Packets', 'Sent Bytes'])
        
        for ip, values in output_data.items():
            csv_writer.writerow([ip, values['received_packets'], values['received_bytes'], values['sent_packets'], values['sent_bytes']])

if __name__ == "__main__":
    input_file_path = 'input.csv'
    output_file_path = 'output.csv'

    input_data = read_csv(input_file_path)
    processed_data = process_data(input_data)
    write_csv(processed_data, output_file_path)

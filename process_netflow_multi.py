import os
import multiprocessing
from parser import parse_netflow_data

def parse_netflow_data(flow_data):
    """Process a flow of data (38 lines) into a parsed format."""
    flow_records = []
    current_record = []
    flow_size = 0  # To track the size of the flow (38 lines)
    for line in flow_data:
        line = line.strip()
        if line.startswith("Flow Record"):
            # If there is a current flow being collected, process it
            if current_record:
                flow_records.append(current_record)
                current_record = []  # Reset for the next flow
            current_record.append(line)
            flow_size = 1  # Start counting the flow size (including this line)
        else:
            current_record.append(line)
            flow_size += 1
            # When the flow size reaches 38, process the flow and reset
            if flow_size == 38:
                flow_records.append(current_record)
                current_record = []  # Reset for the next flow

    # Add the last flow record if exists
    if current_record:
        flow_records.append(current_record)
    
    return flow_records

def process_chunk(chunk_data):
    """Process a chunk of flow data."""
    return parse_netflow_data(chunk_data)

def read_file_in_chunks(file_path, chunk_size=38):
    """Read the file in chunks of the given chunk_size."""
    with open(file_path, 'r') as file:
        file_size = os.path.getsize(file_path)
        current_pos = 0
        while current_pos < file_size:
            file.seek(current_pos)
            chunk_data = []
            # Read chunk_size lines for the current chunk
            for _ in range(chunk_size):
                line = file.readline().strip()
                if line:
                    chunk_data.append(line)
                if not line:  # End of file reached
                    break
            current_pos = file.tell()  # Move the file pointer to the next position
            if chunk_data:
                yield chunk_data

def parse_and_process_file(file_path):
    """Main function to read file, chunk it, and process using multiprocessing."""
    flow_records = []
    num_workers = multiprocessing.cpu_count()
    with multiprocessing.Pool(processes=num_workers) as pool:
        result_queue = []

        # Read the file in chunks and process the chunks using multiprocessing
        for chunk in read_file_in_chunks(file_path, chunk_size=22):
            result = pool.apply_async(process_chunk, args=(chunk,))
            result_queue.append(result)

        # Collect the results
        for result in result_queue:
            flow_records.extend(result.get())
    return flow_records

# Example usage
file_path = "/home/ren/flows_with_v5910"  # Replace with your actual file path
flow_data_chunks = parse_and_process_file(file_path)

# Process each flow record and print the parsed data
for flow_data in flow_data_chunks:
    print(flow_data)


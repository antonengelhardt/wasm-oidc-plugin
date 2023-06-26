import csv
import requests
import threading
import time
import sys
from datetime import datetime

# Function for making requests
def make_request(thread_id, cookie):
    headers = {'Cookie': f'oidcSession={cookie}'}
    for i in range(100):
        start_time = datetime.now()
        try:
            response = requests.get('http://localhost:10000', headers=headers)
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds() * 1000  # convert to milliseconds
            with lock:
                writer.writerow([start_time, end_time, duration, response.status_code])
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds() * 1000  # convert to milliseconds
            with lock:
                writer.writerow([start_time, end_time, duration, 'ERROR', str(e)])
        # Sleep for 0.1 second to avoid overloading the server
        time.sleep(0.1)

# Check command line arguments
if len(sys.argv) != 2:
    print("Usage: python main.py <cookie-value>")
    sys.exit(1)

# Get the cookie value from command line arguments
cookie = sys.argv[1]

# Create the csv writer
filename = 'results-' + datetime.now().strftime('%Y-%m-%d-%H-%M-%S') + '.csv'
file = open(filename, 'w', newline='')
writer = csv.writer(file)
writer.writerow(["start_time", "end_time", "duration_ms", "status_code"])

# Define a lock object to ensure that threads write to the file one at a time
lock = threading.Lock()

# Create and start 10 threads
threads = []
for i in range(10):
    thread = threading.Thread(target=make_request, args=(i, cookie,))
    thread.start()
    threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Close the file
file.close()

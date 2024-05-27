# import matplotlib.pyplot as plt
# import numpy as np

# # Data from the provided records for AES
# aes_times = {
#     '256KB': 2.3944,  # Converted from 2394400 ns
#     '512KB': 8.9518,  # Estimated based on provided data (from 8951800 ns)
#     '1MB': 28.9257,  # Converted from 28925700 ns
#     '5MB': 128.45    # Placeholder (example)
# }

# # Placeholder data for DES and Multiparty FHE (adjust these as needed)
# des_times = {
#     '256KB': 3.2,   # Placeholder value
#     '512KB': 6.5,   # Placeholder value
#     '1MB': 27.5,    # Placeholder value
#     '5MB': 45.3     # Placeholder value
# }

# fhe_times = {
#     '256KB': 4.5,   # Placeholder value
#     '512KB': 8.1,   # Placeholder value
#     '1MB': 30.6,    # Placeholder value
#     '5MB': 50.2     # Placeholder value
# }

# # File sizes
# file_sizes = list(aes_times.keys())

# # Prepare data for plotting, replacing None with 0 for plotting purposes
# aes_times_list = [aes_times[size] if aes_times[size] is not None else 0 for size in file_sizes]
# des_times_list = [des_times[size] if des_times[size] is not None else 0 for size in file_sizes]
# fhe_times_list = [fhe_times[size] if fhe_times[size] is not None else 0 for size in file_sizes]

# # Plotting the data
# x = np.arange(len(file_sizes))
# width = 0.25

# fig, ax = plt.subplots(figsize=(12, 7))

# rects1 = ax.bar(x - width, aes_times_list, width, label='AES', color='skyblue')
# rects2 = ax.bar(x, des_times_list, width, label='DES', color='orange')
# rects3 = ax.bar(x + width, fhe_times_list, width, label='Multiparty FHE', color='green')

# # Adding some text for labels, title, and custom x-axis tick labels, etc.
# ax.set_xlabel('Different Text File')
# ax.set_ylabel('Time (ms)')
# ax.set_title('Encryption time vs. File size for AES, DES, and Multiparty FHE')
# ax.set_xticks(x)
# ax.set_xticklabels(file_sizes)
# ax.legend()

# # Adding data labels
# def autolabel(rects):
#     for rect in rects:
#         height = rect.get_height()
#         ax.annotate(f'{height:.2f}',
#                     xy=(rect.get_x() + rect.get_width() / 2, height),
#                     xytext=(0, 3),  # 3 points vertical offset
#                     textcoords="offset points",
#                     ha='center', va='bottom')

# autolabel(rects1)
# autolabel(rects2)
# autolabel(rects3)

# fig.tight_layout()

# plt.show()


# import matplotlib.pyplot as plt
# import numpy as np

# # Provided records for AES
# records_aes = [
#     "File Name: test_data4.txt, File Size: 640970 bytes, Encryption Time: 8951800 ns, Decryption Time: 8346401 ns",
#     "File Name: 157204731_ExamForm.PDF, File Size: 256697 bytes, Encryption Time: 2394400 ns, Decryption Time: 2482000 ns",
#     "File Name: UML_3.png, File Size: 74799 bytes, Encryption Time: 979200 ns, Decryption Time: 871600 ns",
#     "File Name: windows_10_cmake_Release_graphviz-install-11.0.0-win64.exe, File Size: 5101654 bytes, Encryption Time: 28925700 ns, Decryption Time: 26617000 ns",
#     "File Name: Test.zip, File Size: 219541 bytes, Encryption Time: 1284500 ns, Decryption Time: 1086800 ns"
# ]

# # Function to parse records
# def parse_record(record):
#     parts = record.split(", ")
#     extension = parts[0].split(".")[-1]
#     encryption_time = int(parts[2].split(": ")[1].split()[0]) / 1e6  # Convert to ms
#     decryption_time = int(parts[3].split(": ")[1].split()[0]) / 1e6  # Convert to ms
#     return extension, encryption_time, decryption_time

# # Aggregate records for AES
# aes_times = {}
# for record in records_aes:
#     ext, enc_time, dec_time = parse_record(record)
#     aes_times[ext] = {'encryption': enc_time, 'decryption': dec_time}

# # Hypothetical data for DES and Multiparty FHE (replace with actual data if available)
# des_times = {
#     'txt': {'encryption': 10.0, 'decryption': 9.5},  # Placeholder values
#     'PDF': {'encryption': 4.0, 'decryption': 3.8},   # Placeholder values
#     'png': {'encryption': 2.0, 'decryption': 1.8},   # Placeholder values
#     'exe': {'encryption': 30.0, 'decryption': 28.0}, # Placeholder values
#     'zip': {'encryption': 5.0, 'decryption': 4.5}    # Placeholder values
# }

# fhe_times = {
#     'txt': {'encryption': 15.0, 'decryption': 14.0},  # Placeholder values
#     'PDF': {'encryption': 5.0, 'decryption': 4.7},    # Placeholder values
#     'png': {'encryption': 3.0, 'decryption': 2.7},    # Placeholder values
#     'exe': {'encryption': 35.0, 'decryption': 33.0},  # Placeholder values
#     'zip': {'encryption': 7.0, 'decryption': 6.5}     # Placeholder values
# }

# # File extensions
# file_extensions = list(aes_times.keys())

# # Prepare data for plotting
# aes_enc_times = [aes_times[ext]['encryption'] for ext in file_extensions]
# des_enc_times = [des_times[ext]['encryption'] for ext in file_extensions]
# fhe_enc_times = [fhe_times[ext]['encryption'] for ext in file_extensions]

# # Plotting the data
# x = np.arange(len(file_extensions))
# width = 0.3

# fig, ax = plt.subplots(figsize=(10, 6))

# rects1 = ax.bar(x - width/2, aes_enc_times, width, label='AES Encryption', color='skyblue')
# rects2 = ax.bar(x + width/2, des_enc_times, width, label='DES Encryption', color='orange')
# rects3 = ax.bar(x + 3*width/2, fhe_enc_times, width, label='Multiparty FHE Encryption', color='green')

# # Adding some text for labels, title, and custom x-axis tick labels, etc.
# ax.set_xlabel('File Extensions')
# ax.set_ylabel('Time (ms)')
# ax.set_title('Encryption Times by File Extension for AES, DES, and Multiparty FHE')
# ax.set_xticks(x)
# ax.set_xticklabels(file_extensions)
# ax.legend()

# # Adding data labels
# def autolabel(rects):
#     for rect in rects:
#         height = rect.get_height()
#         ax.annotate(f'{height:.2f}',
#                     xy=(rect.get_x() + rect.get_width() / 2, height),
#                     xytext=(0, 3),  # 3 points vertical offset
#                     textcoords="offset points",
#                     ha='center', va='bottom')

# autolabel(rects1)
# autolabel(rects2)
# autolabel(rects3)

# fig.tight_layout()

# plt.show()


import matplotlib.pyplot as plt
import numpy as np

# Provided records for AES
records_aes = [
    "File Name: test_data4.txt, File Size: 640970 bytes, Encryption Time: 8951800 ns, Decryption Time: 8346401 ns",
    "File Name: 157204731_ExamForm.PDF, File Size: 256697 bytes, Encryption Time: 2394400 ns, Decryption Time: 2482000 ns",
    "File Name: UML_3.png, File Size: 74799 bytes, Encryption Time: 979200 ns, Decryption Time: 871600 ns",
    "File Name: windows_10_cmake_Release_graphviz-install-11.0.0-win64.exe, File Size: 5101654 bytes, Encryption Time: 28925700 ns, Decryption Time: 26617000 ns",
    "File Name: Test.zip, File Size: 219541 bytes, Encryption Time: 1284500 ns, Decryption Time: 1086800 ns"
]

# Function to parse records
def parse_record(record):
    parts = record.split(", ")
    extension = parts[0].split(".")[-1]
    encryption_time = int(parts[2].split(": ")[1].split()[0]) / 1e6  # Convert to ms
    decryption_time = int(parts[3].split(": ")[1].split()[0]) / 1e6  # Convert to ms
    return extension, encryption_time, decryption_time

# Aggregate records for AES
aes_times = {}
for record in records_aes:
    ext, enc_time, dec_time = parse_record(record)
    aes_times[ext] = {'encryption': enc_time, 'decryption': dec_time}

# Hypothetical data for DES and Multiparty FHE (replace with actual data if available)
des_times = {
    'txt': {'encryption': 10.0, 'decryption': 9.5},  # Placeholder values
    'PDF': {'encryption': 4.0, 'decryption': 3.8},   # Placeholder values
    'png': {'encryption': 2.0, 'decryption': 1.8},   # Placeholder values
    'exe': {'encryption': 30.0, 'decryption': 28.0}, # Placeholder values
    'zip': {'encryption': 5.0, 'decryption': 4.5}    # Placeholder values
}

fhe_times = {
    'txt': {'encryption': 15.0, 'decryption': 14.0},  # Placeholder values
    'PDF': {'encryption': 5.0, 'decryption': 4.7},    # Placeholder values
    'png': {'encryption': 3.0, 'decryption': 2.7},    # Placeholder values
    'exe': {'encryption': 35.0, 'decryption': 33.0},  # Placeholder values
    'zip': {'encryption': 7.0, 'decryption': 6.5}     # Placeholder values
}

# File extensions
file_extensions = list(aes_times.keys())

# Prepare data for plotting
aes_dec_times = [aes_times[ext]['decryption'] for ext in file_extensions]
des_dec_times = [des_times[ext]['decryption'] for ext in file_extensions]
fhe_dec_times = [fhe_times[ext]['decryption'] for ext in file_extensions]

# Plotting the data
x = np.arange(len(file_extensions))
width = 0.3

fig, ax = plt.subplots(figsize=(10, 6))

rects1 = ax.bar(x - width/2, aes_dec_times, width, label='AES Decryption', color='skyblue', alpha=0.7)
rects2 = ax.bar(x + width/2, des_dec_times, width, label='DES Decryption', color='orange', alpha=0.7)
rects3 = ax.bar(x + 3*width/2, fhe_dec_times, width, label='Multiparty FHE Decryption', color='green', alpha=0.7)

# Adding some text for labels, title, and custom x-axis tick labels, etc.
ax.set_xlabel('File Extensions')
ax.set_ylabel('Time (ms)')
ax.set_title('Decryption Times by File Extension for AES, DES, and Multiparty FHE')
ax.set_xticks(x)
ax.set_xticklabels(file_extensions)
ax.legend()

# Adding data labels
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height:.2f}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

autolabel(rects1)
autolabel(rects2)
autolabel(rects3)

fig.tight_layout()

plt.show()

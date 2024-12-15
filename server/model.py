import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle
import warnings

# Ignore all warnings
warnings.filterwarnings("ignore")

# Example data (assuming you have a DataFrame with the extracted features)
df1 = pd.DataFrame(pd.read_excel('Features_Training_Initial_55.xlsx'))
df21 = pd.DataFrame(pd.read_excel('Splitted_Features_Training_Final_30_1.xlsx'))
df22 = pd.DataFrame(pd.read_excel('Splitted_Features_Training_Final_30_2.xlsx'))
df23 = pd.DataFrame(pd.read_excel('Splitted_Features_Training_Final_30_3.xlsx'))
df24 = pd.DataFrame(pd.read_excel('Splitted_Features_Training_Final_30_4.xlsx'))
df25 = pd.DataFrame(pd.read_excel('Splitted_Features_Training_Final_30_5.xlsx'))
df26 = pd.DataFrame(pd.read_excel('Splitted_Features_Training_Final_30_6.xlsx'))
df2 = pd.concat([df21, df22, df23, df24, df25, df26], axis=0)


df1_columns = set(df1.columns)
df2_columns = set(df2.columns)
common_columns = df1_columns.intersection(df2_columns)


df2 = df2.reset_index(drop=True)

df2.drop(columns=['mode', 'iv', 'Encrypted Data (Hex)', 'Encrypted Data (Binary)', 'Original Text', 'Length', 'Algorithm'], inplace=True)
df = pd.concat([df1, df2], axis=1)


import numpy as np

from collections import Counter

def get_block_size(ciphertext_hex):
    # Step 1: Convert the hex string to bytes
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    # Step 2: Get the length of the ciphertext in bytes
    ciphertext_length = len(ciphertext_bytes)

    # Step 3: Check the length of the ciphertext and infer the block size
    # print(f"Ciphertext length in bytes: {ciphertext_length}")

    if ciphertext_length % 16 == 0:
        return 16
    elif ciphertext_length % 8 == 0:
        return 8
    else:
        return 0

# Function to calculate the block frequency (check repetition)
def calculate_block_frequency(ciphertext, block_size=8):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    block_counter = Counter(tuple(block) for block in blocks)

    # Calculate the percentage of repeated blocks
    repeated_blocks = sum(count > 1 for count in block_counter.values())
    total_blocks = len(blocks)
    return repeated_blocks / total_blocks * 100

block_size_list = []
block_cipher_boolean_list = []
block_frequency_list = []

for i in df['Encrypted Data (Hex)']:
    block_size = get_block_size(i)
    block_size_list.append(block_size)
    if (block_size != 0):
        block_cipher_boolean_list.append(1)
    else:
        block_cipher_boolean_list.append(0)
    if (block_size == 8):
        block_frequency_list.append(calculate_block_frequency(i, block_size))
    else:
        block_frequency_list.append(0)
df['block_size'] = block_size_list
df['block_cipher_boolean'] = block_cipher_boolean_list
df['block_frequency'] = block_frequency_list

import numpy as np
import math
import itertools
import pandas as pd
from scipy import special

# Function to convert Hex to Binary
def hex_to_binary(hex_data):
    return ''.join(format(byte, '08b') for byte in bytes.fromhex(hex_data))

# Frequency Test (Monobit Test)
def frequency_test(binary_sequence):
    """
    Checks the proportion of 0s and 1s in the binary sequence

    Args:
        binary_sequence (str): Binary sequence of 0s and 1s

    Returns:
        float: p-value indicating randomness
    """
    n = len(binary_sequence)
    s = np.sum([int(bit) for bit in binary_sequence])
    s_obs = abs(s - n/2) / np.sqrt(n/4)

    # Calculate p-value
    p_value = math.erfc(s_obs / np.sqrt(2))
    return p_value

# Runs Test
def runs_test(binary_sequence):
    """
    Analyzes the number of runs (consecutive sequences of the same bit)

    Args:
        binary_sequence (str): Binary sequence of 0s and 1s

    Returns:
        float: p-value indicating randomness
    """
    n = len(binary_sequence)
    pi = np.mean([int(bit) for bit in binary_sequence])

    # Calculate the number of runs
    runs = 1
    for i in range(1, n):
        if binary_sequence[i] != binary_sequence[i-1]:
            runs += 1

    # Calculate test statistic
    runs_obs = runs
    runs_exp = ((2 * n * pi * (1 - pi)) + 1)
    runs_std = 2 * np.sqrt(2 * n * pi * (1 - pi)) - (1/2)

    z = (runs_obs - runs_exp) / runs_std

    # Calculate p-value
    p_value = math.erfc(abs(z) / np.sqrt(2))
    return p_value

# Longest Run of Ones Test
def longest_run_test(binary_sequence):
    """
    Checks the longest run of consecutive 1s in the sequence

    Args:
        binary_sequence (str): Binary sequence of 0s and 1s

    Returns:
        float: p-value indicating randomness
    """
    # Split sequence into blocks
    k = 6  # Number of blocks
    m = 8  # Length of each block

    blocks = [binary_sequence[i:i+m] for i in range(0, len(binary_sequence), m)]

    # Count longest runs in each block
    longest_runs = []
    for block in blocks:
        max_run = 0
        current_run = 0

        # Find the longest run of 1s in the block
        for bit in block:
            if bit == '1':
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 0

        longest_runs.append(max_run)

    # Predefined chi-square distribution parameters
    v_obs = [0, 0, 0, 0]
    for run in longest_runs:
        if run <= 1:
            v_obs[0] += 1
        elif run == 2:
            v_obs[1] += 1
        elif run == 3:
            v_obs[2] += 1
        elif run >= 4:
            v_obs[3] += 1

    # Predefined probabilities for chi-square
    pi = [0.2148, 0.3672, 0.2305, 0.1875]

    # Chi-square calculation
    chi_sq = sum(((v_obs[i] - k * pi[i])**2) / (k * pi[i]) for i in range(4))

    # Calculate p-value
    p_value = special.gammainc(2.5, chi_sq/2)
    return p_value

# Function to calculate cryptographic features
def extract_features(hex_data):
    binary_data = hex_to_binary(hex_data)

    # Perform NIST randomness tests
    freq_p_value = frequency_test(binary_data)
    runs_p_value = runs_test(binary_data)
    longest_run_p_value = longest_run_test(binary_data)



    # Combine all the extracted features into a dictionary
    features = {
        'nist_frequency_test_p_value': freq_p_value,
        'nist_runs_test_p_value': runs_p_value,
        'nist_longest_run_test_p_value': longest_run_p_value,

    }

    return features

# Assuming 'Encrypted Data (Hex)' column exists in the DataFrame
nist_p_values_list = []
nist_p_values_runs_test_list = []
nist_p_values_longest_run_list = []

for i in df['Encrypted Data (Hex)']:
    features = extract_features(i)

    nist_p_values_list.append(features['nist_frequency_test_p_value'])
    nist_p_values_runs_test_list.append(features['nist_runs_test_p_value'])
    nist_p_values_longest_run_list.append(features['nist_longest_run_test_p_value'])


# Add the results to the dataframe
df['nist_frequency_test_p_value'] = nist_p_values_list
df['nist_runs_test_p_value'] = nist_p_values_runs_test_list
df['nist_longest_run_test_p_value'] = nist_p_values_longest_run_list



# count = 0
# total = 0
# for i in range(0, len(df['Algorithm'])):
#     if (df['Algorithm'][i] == 'AES'):
#         total = total + 1
#         # print(df['block_size'][i])
#         if (df['block_size'][i] == 16):
#             count = count + 1
# print(count / total)



y_train = df['Algorithm']
df.drop(columns=['Original Text', 'Length', 'Encrypted Data (Binary)', 'Encrypted Data (Hex)', 'Algorithm', 'iv'], inplace=True)
X_train = df



"""#**Input (Testing)**

"""

# Example data (assuming you have a DataFrame with the extracted features)
df1 = pd.DataFrame(pd.read_excel('Features_Testing_Initial_55.xlsx'))
df2 = pd.DataFrame(pd.read_excel('Features_Testing_Final_30.xlsx'))


df1_columns = set(df1.columns)
df2_columns = set(df2.columns)
common_columns = df1_columns.intersection(df2_columns)


df2.drop(columns=['mode', 'iv', 'Encrypted Data (Hex)', 'Encrypted Data (Binary)', 'Original Text', 'Length', 'Algorithm'], inplace=True)
df = pd.concat([df1, df2], axis=1)




import numpy as np

from collections import Counter

def get_block_size(ciphertext_hex):
    # Step 1: Convert the hex string to bytes
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    # Step 2: Get the length of the ciphertext in bytes
    ciphertext_length = len(ciphertext_bytes)

    # Step 3: Check the length of the ciphertext and infer the block size
    # print(f"Ciphertext length in bytes: {ciphertext_length}")

    if ciphertext_length % 16 == 0:
        return 16
    elif ciphertext_length % 8 == 0:
        return 8
    else:
        return 0

# Function to calculate the block frequency (check repetition)
def calculate_block_frequency(ciphertext, block_size=8):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    block_counter = Counter(tuple(block) for block in blocks)

    # Calculate the percentage of repeated blocks
    repeated_blocks = sum(count > 1 for count in block_counter.values())
    total_blocks = len(blocks)
    return repeated_blocks / total_blocks * 100

block_size_list = []
block_cipher_boolean_list = []
block_frequency_list = []

for i in df['Encrypted Data (Hex)']:
    block_size = get_block_size(i)
    block_size_list.append(block_size)
    if (block_size != 0):
        block_cipher_boolean_list.append(1)
    else:
        block_cipher_boolean_list.append(0)
    if (block_size == 8):
        block_frequency_list.append(calculate_block_frequency(i, block_size))
    else:
        block_frequency_list.append(0)
df['block_size'] = block_size_list
df['block_cipher_boolean'] = block_cipher_boolean_list
df['block_frequency'] = block_frequency_list

import numpy as np
import math
import itertools
import pandas as pd
from scipy import special

# Function to convert Hex to Binary
def hex_to_binary(hex_data):
    return ''.join(format(byte, '08b') for byte in bytes.fromhex(hex_data))

# Frequency Test (Monobit Test)
def frequency_test(binary_sequence):
    """
    Checks the proportion of 0s and 1s in the binary sequence

    Args:
        binary_sequence (str): Binary sequence of 0s and 1s

    Returns:
        float: p-value indicating randomness
    """
    n = len(binary_sequence)
    s = np.sum([int(bit) for bit in binary_sequence])
    s_obs = abs(s - n/2) / np.sqrt(n/4)

    # Calculate p-value
    p_value = math.erfc(s_obs / np.sqrt(2))
    return p_value

# Runs Test
def runs_test(binary_sequence):
    """
    Analyzes the number of runs (consecutive sequences of the same bit)

    Args:
        binary_sequence (str): Binary sequence of 0s and 1s

    Returns:
        float: p-value indicating randomness
    """
    n = len(binary_sequence)
    pi = np.mean([int(bit) for bit in binary_sequence])

    # Calculate the number of runs
    runs = 1
    for i in range(1, n):
        if binary_sequence[i] != binary_sequence[i-1]:
            runs += 1

    # Calculate test statistic
    runs_obs = runs
    runs_exp = ((2 * n * pi * (1 - pi)) + 1)
    runs_std = 2 * np.sqrt(2 * n * pi * (1 - pi)) - (1/2)

    z = (runs_obs - runs_exp) / runs_std

    # Calculate p-value
    p_value = math.erfc(abs(z) / np.sqrt(2))
    return p_value

# Longest Run of Ones Test
def longest_run_test(binary_sequence):
    """
    Checks the longest run of consecutive 1s in the sequence

    Args:
        binary_sequence (str): Binary sequence of 0s and 1s

    Returns:
        float: p-value indicating randomness
    """
    # Split sequence into blocks
    k = 6  # Number of blocks
    m = 8  # Length of each block

    blocks = [binary_sequence[i:i+m] for i in range(0, len(binary_sequence), m)]

    # Count longest runs in each block
    longest_runs = []
    for block in blocks:
        max_run = 0
        current_run = 0

        # Find the longest run of 1s in the block
        for bit in block:
            if bit == '1':
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 0

        longest_runs.append(max_run)

    # Predefined chi-square distribution parameters
    v_obs = [0, 0, 0, 0]
    for run in longest_runs:
        if run <= 1:
            v_obs[0] += 1
        elif run == 2:
            v_obs[1] += 1
        elif run == 3:
            v_obs[2] += 1
        elif run >= 4:
            v_obs[3] += 1

    # Predefined probabilities for chi-square
    pi = [0.2148, 0.3672, 0.2305, 0.1875]

    # Chi-square calculation
    chi_sq = sum(((v_obs[i] - k * pi[i])**2) / (k * pi[i]) for i in range(4))

    # Calculate p-value
    p_value = special.gammainc(2.5, chi_sq/2)
    return p_value

# Function to calculate cryptographic features
def extract_features(hex_data):
    binary_data = hex_to_binary(hex_data)

    # Perform NIST randomness tests
    freq_p_value = frequency_test(binary_data)
    runs_p_value = runs_test(binary_data)
    longest_run_p_value = longest_run_test(binary_data)



    # Combine all the extracted features into a dictionary
    features = {
        'nist_frequency_test_p_value': freq_p_value,
        'nist_runs_test_p_value': runs_p_value,
        'nist_longest_run_test_p_value': longest_run_p_value,

    }

    return features

# Assuming 'Encrypted Data (Hex)' column exists in the DataFrame
nist_p_values_list = []
nist_p_values_runs_test_list = []
nist_p_values_longest_run_list = []

for i in df['Encrypted Data (Hex)']:
    features = extract_features(i)

    nist_p_values_list.append(features['nist_frequency_test_p_value'])
    nist_p_values_runs_test_list.append(features['nist_runs_test_p_value'])
    nist_p_values_longest_run_list.append(features['nist_longest_run_test_p_value'])


# Add the results to the dataframe
df['nist_frequency_test_p_value'] = nist_p_values_list
df['nist_runs_test_p_value'] = nist_p_values_runs_test_list
df['nist_longest_run_test_p_value'] = nist_p_values_longest_run_list

"""##Preparing Testing Dataset"""

y_test = df['Algorithm']
df.drop(columns=['Original Text', 'Length', 'Encrypted Data (Binary)', 'Encrypted Data (Hex)', 'Algorithm', 'iv'], inplace=True)
X_test = df


"""#**Data Preprocessing and Feature Engineering (from Object Columns) for Training Dataset**"""





# import numpy as np
# from sklearn.impute import SimpleImputer

# imputer = SimpleImputer(missing_values=np.nan, strategy='median')
# X_train['block_size'] = imputer.fit_transform(X_train[['block_size']])
# X_train.isnull().sum()

from sklearn.preprocessing import LabelEncoder

label_encoder1 = LabelEncoder()
label_encoder1.fit(X_train[['mode']])
def label_encoder1_function():
    return label_encoder1
X_train['mode'] = label_encoder1.transform(X_train[['mode']])




import numpy as np
from scipy.stats import entropy
from scipy.stats import skew, kurtosis
byte_value_histogram_mean_list = []
byte_value_histogram_std_dev_list = []
byte_distribution_entropy_list = []
byte_distribution_uniformity_score_list = []
byte_distribution_peak_to_mean_ratio_list = []
byte_distribution_low_frequency_byte_count_list = []
byte_distribution_skewness_list = []
byte_distribution_kurtosis_list = []
byte_distribution_dominant_byte_frequency_list = []
byte_distribution_byte_range_spread_list = []
for i in X_train['byte_value_histogram']:
    l = i.split(', ')
    l1 = []
    for j in l:
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        l1.append(int(j))
    byte_value_histogram_mean_list.append(sum(l1)/len(l1))
    byte_value_histogram_std_dev_list.append(np.std(l1))
    total_sum = sum(l1)
    byte_distribution = [i / total_sum for i in l1]
    byte_distribution_entropy_list.append(entropy(byte_distribution, base=2))
    ideal_uniform = 1 / 256
    byte_distribution_uniformity_score_list.append(1 - np.sum(np.abs(np.array(byte_distribution) - ideal_uniform)) / 2)
    mean_frequency = np.mean(byte_distribution)
    peak_frequency = max(byte_distribution)
    byte_distribution_peak_to_mean_ratio_list.append(peak_frequency / mean_frequency)
    byte_distribution_low_frequency_byte_count_list.append(sum(1 for freq in byte_distribution if freq < 0.001))
    byte_distribution_skewness_list.append(skew(byte_distribution))
    byte_distribution_kurtosis_list.append(kurtosis(byte_distribution))
    byte_distribution_dominant_byte_frequency_list.append(max(byte_distribution))
    byte_distribution_byte_range_spread_list.append(max(byte_distribution) - min(byte_distribution))
byte_value_histogram_mean_df = pd.DataFrame(byte_value_histogram_mean_list, columns=['byte_value_histogram_mean'])
byte_value_histogram_std_dev_df = pd.DataFrame(byte_value_histogram_std_dev_list, columns=['byte_value_histogram_std_dev'])
byte_distribution_entropy_df = pd.DataFrame(byte_distribution_entropy_list, columns=['byte_distribution_entropy'])
byte_distribution_uniformity_score_df = pd.DataFrame(byte_distribution_uniformity_score_list, columns=['byte_distribution_uniformity_score'])
byte_distribution_peak_to_mean_ratio_df = pd.DataFrame(byte_distribution_peak_to_mean_ratio_list, columns=['byte_distribution_peak_to_mean_ratio'])
byte_distribution_low_frequency_byte_count_df = pd.DataFrame(byte_distribution_low_frequency_byte_count_list, columns=['byte_distribution_low_frequency_byte_count'])
byte_distribution_skewness_df = pd.DataFrame(byte_distribution_skewness_list, columns=['byte_distribution_skewness'])
byte_distribution_kurtosis_df = pd.DataFrame(byte_distribution_kurtosis_list, columns=['byte_distribution_kurtosis'])
byte_distribution_dominant_byte_frequency_df = pd.DataFrame(byte_distribution_dominant_byte_frequency_list, columns=['byte_distribution_dominant_byte_frequency'])
byte_distribution_byte_range_spread_df = pd.DataFrame(byte_distribution_byte_range_spread_list, columns=['byte_distribution_byte_range_spread'])
X_train = pd.concat([X_train, byte_value_histogram_mean_df, byte_value_histogram_std_dev_df, byte_distribution_entropy_df, byte_distribution_uniformity_score_df, byte_distribution_peak_to_mean_ratio_df, byte_distribution_low_frequency_byte_count_df, byte_distribution_skewness_df, byte_distribution_kurtosis_df, byte_distribution_dominant_byte_frequency_df, byte_distribution_byte_range_spread_df], axis=1)




X_train.drop(columns=['byte_value_histogram'], inplace=True)



import numpy as np
byte_value_25th_percentile_list = []
byte_value_50th_percentile_list = []
byte_value_75th_percentile_list = []
for i in X_train['byte_value_percentiles']:
    l = i.split(', ')
    l1 = []
    for j in l:
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        l1.append(float(j))
    byte_value_25th_percentile_list.append(l1[0])
    byte_value_50th_percentile_list.append(l1[1])
    byte_value_75th_percentile_list.append(l1[2])
byte_value_25th_percentile_df = pd.DataFrame(byte_value_25th_percentile_list, columns=['byte_value_25th_percentile'])
byte_value_50th_percentile_df = pd.DataFrame(byte_value_50th_percentile_list, columns=['byte_value_50th_percentile'])
byte_value_75th_percentile_df = pd.DataFrame(byte_value_75th_percentile_list, columns=['byte_value_75th_percentile'])
X_train = pd.concat([X_train, byte_value_25th_percentile_df, byte_value_50th_percentile_df, byte_value_75th_percentile_df], axis=1)




X_train.drop(columns='byte_value_percentiles', inplace=True)





import numpy as np
freq_byte_value_diff_mean_keys_list = []
freq_byte_value_diff_mean_values_list = []
freq_byte_value_diff_weighted_mean_list = []
freq_byte_value_diff_max_keys_list = []
freq_byte_value_diff_max_values_list = []
freq_byte_value_diff_std_dev_keys_list = []
for i in X_train['freq_byte_value_diff']:
    l = i.split(', ')
    d = {}
    for j in l:
        if (j[0] == '{'):
            j = j[1:]
        if (j[-1] == '}'):
            j = j[:-1]
        l1 = j.split(': ')
        d[int(l1[0])] = int(l1[1])
    freq_byte_value_diff_mean_keys_list.append(np.mean(list(d.keys())))
    freq_byte_value_diff_mean_values_list.append(np.mean(list(d.values())))
    freq_byte_value_diff_weighted_mean_list.append(np.average(list(d.keys()), weights=list(d.values())))
    freq_byte_value_diff_max_keys_list.append(max(list(d.keys())))
    freq_byte_value_diff_max_values_list.append(max(list(d.values())))
    freq_byte_value_diff_std_dev_keys_list.append(np.std(list(d.keys())))
freq_byte_value_diff_mean_keys_df = pd.DataFrame(freq_byte_value_diff_mean_keys_list, columns=['freq_byte_value_diff_mean_keys'])
freq_byte_value_diff_mean_values_df = pd.DataFrame(freq_byte_value_diff_mean_values_list, columns=['freq_byte_value_diff_mean_values'])
freq_byte_value_diff_weighted_mean_df = pd.DataFrame(freq_byte_value_diff_weighted_mean_list, columns=['freq_byte_value_diff_weighted_mean'])
freq_byte_value_diff_max_keys_df = pd.DataFrame(freq_byte_value_diff_max_keys_list, columns=['freq_byte_value_diff_max_keys'])
freq_byte_value_diff_max_values_df = pd.DataFrame(freq_byte_value_diff_max_values_list, columns=['freq_byte_value_diff_max_values'])
freq_byte_value_diff_std_dev_keys_df = pd.DataFrame(freq_byte_value_diff_std_dev_keys_list, columns=['freq_byte_value_diff_std_dev_keys'])
X_train = pd.concat([X_train, freq_byte_value_diff_mean_keys_df, freq_byte_value_diff_mean_values_df, freq_byte_value_diff_weighted_mean_df, freq_byte_value_diff_max_keys_df, freq_byte_value_diff_max_values_df, freq_byte_value_diff_std_dev_keys_df], axis=1)




X_train.drop(columns=['freq_byte_value_diff'], inplace=True)



import numpy as np
run_length_encoding_total_encoding_length_list = []
run_length_encoding_max_run_length_list = []
run_length_encoding_mean_run_length_list = []
run_length_encoding_std_dev_run_length_list = []
run_length_encoding_mean_value_list = []
run_length_encoding_std_dev_value_list = []
for i in X_train['run_length_encoding']:
    l = i.split(', ')
    run = []
    value = []
    parity = 0
    for j in l:
        if (j == ''):
            run.append(0)
            value.append(0)
            continue
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        if (parity == 0):
            j = j[1:]
            if ((len(j) > 1) and (j[-1] == ',')):
                j = j[:-1]
            if (j == ''):
                run.append(0)
            else:
                run.append(int(j))
            parity = 1
        else:
            j = j[:-1]
            if ((len(j) > 1) and (j[-1] == ',')):
                j = j[:-1]
            if (j == ''):
                value.append(0)
            else:
                if (j[-1] == ')'):
                    j = j[:-1]
                value.append(int(j))
            parity = 0
    run_length_encoding_total_encoding_length_list.append(sum(run))
    run_length_encoding_max_run_length_list.append(max(run))
    run_length_encoding_mean_run_length_list.append(np.mean(run))
    run_length_encoding_std_dev_run_length_list.append(np.std(run))
    run_length_encoding_mean_value_list.append(np.mean(value))
    run_length_encoding_std_dev_value_list.append(np.std(value))
run_length_encoding_total_encoding_length_df = pd.DataFrame(run_length_encoding_total_encoding_length_list, columns=['run_length_encoding_total_encoding_length'])
run_length_encoding_max_run_length_df = pd.DataFrame(run_length_encoding_max_run_length_list, columns=['run_length_encoding_max_run_length'])
run_length_encoding_mean_run_length_df = pd.DataFrame(run_length_encoding_mean_run_length_list, columns=['run_length_encoding_mean_run_length'])
run_length_encoding_std_dev_run_length_df = pd.DataFrame(run_length_encoding_std_dev_run_length_list, columns=['run_length_encoding_std_dev_run_length'])
run_length_encoding_mean_value_df = pd.DataFrame(run_length_encoding_mean_value_list, columns=['run_length_encoding_mean_value'])
run_length_encoding_std_dev_value_df = pd.DataFrame(run_length_encoding_std_dev_value_list, columns=['run_length_encoding_std_dev_value'])
X_train = pd.concat([X_train, run_length_encoding_total_encoding_length_df, run_length_encoding_max_run_length_df, run_length_encoding_mean_run_length_df, run_length_encoding_std_dev_run_length_df, run_length_encoding_mean_value_df, run_length_encoding_std_dev_value_df], axis=1)




X_train.drop(columns=['run_length_encoding'], inplace=True)



from scipy.stats import entropy
import numpy as np
byte_value_transition_matrix_sparsity_list = []
byte_value_transition_matrix_entropy_list = []
byte_value_transition_matrix_top_k_sum_list = []
byte_value_transition_matrix_mean_prob_per_row_list = []
byte_value_transition_matrix_quadrant_1_sum_list = []
byte_value_transition_matrix_quadrant_2_sum_list = []
byte_value_transition_matrix_quadrant_3_sum_list = []
byte_value_transition_matrix_quadrant_4_sum_list = []
for i in X_train['byte_value_transition_matrix']:
    l = []
    l1 = i.split(', ')
    l2 = []
    for j in l1:
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        if ((len(j) > 1) and (j[-1] == ',')):
            j = j[:-1]
        if (type(j) == list):
            l.append(j)
        else:
            l2.append(int(j))
        if (len(l2) == 256):
            l1.append(l2)
            l2 = []
    l = np.array(l)
    sparsity = 1 - np.count_nonzero(l) / (256 * 256)
    byte_value_transition_matrix_sparsity_list.append(sparsity)
    prob_matrix = l / np.sum(l)
    byte_value_transition_matrix_entropy_list.append(entropy(prob_matrix.flatten(), base=2))
    top_k_transitions = np.sort(l.flatten())[::-1][:5]  # Sum of top 5
    top_k_sum = np.sum(top_k_transitions)
    byte_value_transition_matrix_top_k_sum_list.append(top_k_sum)
    normalized_matrix = l / (np.sum(l, axis=1, keepdims=True) + 1e-10)
    byte_value_transition_matrix_mean_prob_per_row_list.append(np.mean(normalized_matrix, axis=1).mean())
    byte_value_transition_matrix_quadrant_1_sum_list.append(np.sum(l[:128, :128]))  # Top-left
    byte_value_transition_matrix_quadrant_2_sum_list.append(np.sum(l[:128, 128:]))  # Top-right
    byte_value_transition_matrix_quadrant_3_sum_list.append(np.sum(l[128:, :128]))  # Bottom-left
    byte_value_transition_matrix_quadrant_4_sum_list.append(np.sum(l[128:, 128:]))  # Bottom-right
byte_value_transition_matrix_sparsity_df = pd.DataFrame(byte_value_transition_matrix_sparsity_list, columns=['byte_value_transition_matrix_sparsity'])
byte_value_transition_matrix_entropy_df = pd.DataFrame(byte_value_transition_matrix_entropy_list, columns=['byte_value_transition_matrix_entropy'])
byte_value_transition_matrix_top_k_sum_df = pd.DataFrame(byte_value_transition_matrix_top_k_sum_list, columns=['byte_value_transition_matrix_top_k_sum'])
byte_value_transition_matrix_mean_prob_per_row_df = pd.DataFrame(byte_value_transition_matrix_mean_prob_per_row_list, columns=['byte_value_transition_matrix_mean_prob_per_row'])
byte_value_transition_matrix_quadrant_1_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_1_sum_list, columns=['byte_value_transition_matrix_quadrant_1_sum'])
byte_value_transition_matrix_quadrant_2_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_2_sum_list, columns=['byte_value_transition_matrix_quadrant_2_sum'])
byte_value_transition_matrix_quadrant_3_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_3_sum_list, columns=['byte_value_transition_matrix_quadrant_3_sum'])
byte_value_transition_matrix_quadrant_4_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_4_sum_list, columns=['byte_value_transition_matrix_quadrant_4_sum'])
X_train = pd.concat([X_train, byte_value_transition_matrix_sparsity_df, byte_value_transition_matrix_entropy_df, byte_value_transition_matrix_top_k_sum_df, byte_value_transition_matrix_mean_prob_per_row_df, byte_value_transition_matrix_quadrant_1_sum_df, byte_value_transition_matrix_quadrant_2_sum_df, byte_value_transition_matrix_quadrant_3_sum_df, byte_value_transition_matrix_quadrant_4_sum_df], axis=1)


X_train.drop(columns=['byte_value_transition_matrix'], inplace=True)



# X_train.drop(columns=['byte_value_transition_matrix'], inplace=True)

X_train.drop(columns=['freq_byte_value_2grams', 'freq_byte_value_3grams', 'freq_byte_value_4grams'], inplace=True)



import numpy as np
import pandas as pd
import ast

# Function to summarize ACF for a single ciphertext
def summarize_acf(acf_values):
    # Ensure the input is a list of floats
    acf_values = np.array(acf_values, dtype=np.float64)

    # Exclude lag 0 (self-correlation)
    acf_no_lag0 = acf_values[1:]

    # Compute features
    mean_acf = np.mean(acf_no_lag0)
    variance_acf = np.var(acf_no_lag0)
    max_acf = np.max(acf_no_lag0)
    lag_of_max_acf = np.argmax(acf_no_lag0) + 1  # +1 because we excluded lag 0

    return {
        "mean_acf": mean_acf,
        "variance_acf": variance_acf,
        "max_acf": max_acf,
        "lag_of_max_acf": lag_of_max_acf
    }



# Convert the string representation of a list into an actual list
X_train['byte_value_acf'] = X_train['byte_value_acf'].apply(lambda x: ast.literal_eval(x))

# Apply summarize_acf for each row in 'byte_value_acf' column
features_list = X_train['byte_value_acf'].apply(summarize_acf)

# Convert features_list into a DataFrame
features_df = pd.DataFrame(features_list.tolist())

# Add the new features to the original X_train
X_train = pd.concat([X_train, features_df], axis=1)





X_train.drop(columns=['byte_value_acf'], inplace=True)


import numpy as np
import pandas as pd

# Function to calculate total power (sum of all frequencies)
def total_power(power_spectrum):
    return np.sum(power_spectrum)

# Function to calculate peak power (maximum frequency component)
def peak_power(power_spectrum):
    return np.max(power_spectrum)

# Function to calculate power concentration (ratio of top n frequencies' power to total power)
def power_concentration(power_spectrum, top_n=3):
    sorted_spectrum = np.sort(power_spectrum)[::-1]  # Sort in descending order
    return np.sum(sorted_spectrum[:top_n]) / np.sum(power_spectrum)

# # Example of applying these functions to your data
# X_train = pd.DataFrame({
#     'byte_value_power_spectrum': [
#         [150100455184.0, 10933011.937147308, 17569885.488023052],
#         [60031504.0, 400436.77105714486, 428221.7924971855],
#         [11758041.0, 98795.90679018006, 258054.280108135],
#         [3150625.0, 36711.263661699806, 240051.794852449],
#         [619369.0, 18911.38498657157, 91709.0000000000]
#     ]
# })

l = []
for i in X_train['byte_value_power_spectrum']:
    l1 = []
    l2 = i.split(", ")
    for j in l2:
      if (j == ''):
          l1.append(0)
          continue
      if (j[0] == '['):
          j = j[1:]
      if (j[-1] == ']'):
          j = j[:-1]
      if (j[-1] == ','):
          j = j[:-1]
      l1.append(float(j))
    l.append(l1)
X_train['byte_value_power_spectrum'] = l

# Apply the functions to each row in the 'byte_value_power_spectrum' column
X_train['total_power'] = X_train['byte_value_power_spectrum'].apply(lambda x: total_power(x))
X_train['peak_power'] = X_train['byte_value_power_spectrum'].apply(lambda x: peak_power(x))
X_train['power_concentration'] = X_train['byte_value_power_spectrum'].apply(lambda x: power_concentration(x))



X_train.drop(columns=['byte_value_power_spectrum'], inplace=True)



"""##Feature List

"""


features=list(X_train.columns)


"""##Imputing Null Values in Training Dataset"""



import numpy as np
from sklearn.impute import SimpleImputer

imputer = SimpleImputer(missing_values=np.nan, strategy='median')
X_train['byte_value_transition_matrix_entropy'] = imputer.fit_transform(X_train[['byte_value_transition_matrix_entropy']])

def byte_value_transition_matrix_entropy_imputer():
    return imputer



"""##Extracting Training Dataset for CNN"""

X_train_cnn = X_train
y_train_cnn = y_train

"""##Normalization of Training Dataset"""

from sklearn.preprocessing import StandardScaler
exclude_columns = ['mode', 'block_size', 'block_cipher_boolean', 'block_frequency', 'length', 'byte_distribution_uniformity_score', 'byte_distribution_low_frequency_byte_count', 'byte_distribution_skewness', 'byte_distribution_kurtosis', 'byte_distribution_dominant_byte_frequency', 'byte_distribution_byte_range_spread']
columns_to_scale = X_train.columns.difference(exclude_columns)

scaler = StandardScaler()


scaler.fit(X_train[columns_to_scale])
X_train[columns_to_scale] = scaler.transform(X_train[columns_to_scale])

def scaler_function():
    return scaler

"""#**Data Preprocessing and Feature Engineering (from Object Columns) for Testing Dataset**"""



# import numpy as np
# from sklearn.impute import SimpleImputer

# imputer = SimpleImputer(missing_values=np.nan, strategy='median')
# X_test['block_size'] = imputer.fit_transform(X_test[['block_size']])
# X_test.isnull().sum()

X_test['mode'] = label_encoder1.transform(X_test[['mode']])


import numpy as np
from scipy.stats import entropy
from scipy.stats import skew, kurtosis
byte_value_histogram_mean_list = []
byte_value_histogram_std_dev_list = []
byte_distribution_entropy_list = []
byte_distribution_uniformity_score_list = []
byte_distribution_peak_to_mean_ratio_list = []
byte_distribution_low_frequency_byte_count_list = []
byte_distribution_skewness_list = []
byte_distribution_kurtosis_list = []
byte_distribution_dominant_byte_frequency_list = []
byte_distribution_byte_range_spread_list = []
for i in X_test['byte_value_histogram']:
    l = i.split(', ')
    l1 = []
    for j in l:
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        l1.append(int(j))
    byte_value_histogram_mean_list.append(sum(l1)/len(l1))
    byte_value_histogram_std_dev_list.append(np.std(l1))
    total_sum = sum(l1)
    byte_distribution = [i / total_sum for i in l1]
    byte_distribution_entropy_list.append(entropy(byte_distribution, base=2))
    ideal_uniform = 1 / 256
    byte_distribution_uniformity_score_list.append(1 - np.sum(np.abs(np.array(byte_distribution) - ideal_uniform)) / 2)
    mean_frequency = np.mean(byte_distribution)
    peak_frequency = max(byte_distribution)
    byte_distribution_peak_to_mean_ratio_list.append(peak_frequency / mean_frequency)
    byte_distribution_low_frequency_byte_count_list.append(sum(1 for freq in byte_distribution if freq < 0.001))
    byte_distribution_skewness_list.append(skew(byte_distribution))
    byte_distribution_kurtosis_list.append(kurtosis(byte_distribution))
    byte_distribution_dominant_byte_frequency_list.append(max(byte_distribution))
    byte_distribution_byte_range_spread_list.append(max(byte_distribution) - min(byte_distribution))
byte_value_histogram_mean_df = pd.DataFrame(byte_value_histogram_mean_list, columns=['byte_value_histogram_mean'])
byte_value_histogram_std_dev_df = pd.DataFrame(byte_value_histogram_std_dev_list, columns=['byte_value_histogram_std_dev'])
byte_distribution_entropy_df = pd.DataFrame(byte_distribution_entropy_list, columns=['byte_distribution_entropy'])
byte_distribution_uniformity_score_df = pd.DataFrame(byte_distribution_uniformity_score_list, columns=['byte_distribution_uniformity_score'])
byte_distribution_peak_to_mean_ratio_df = pd.DataFrame(byte_distribution_peak_to_mean_ratio_list, columns=['byte_distribution_peak_to_mean_ratio'])
byte_distribution_low_frequency_byte_count_df = pd.DataFrame(byte_distribution_low_frequency_byte_count_list, columns=['byte_distribution_low_frequency_byte_count'])
byte_distribution_skewness_df = pd.DataFrame(byte_distribution_skewness_list, columns=['byte_distribution_skewness'])
byte_distribution_kurtosis_df = pd.DataFrame(byte_distribution_kurtosis_list, columns=['byte_distribution_kurtosis'])
byte_distribution_dominant_byte_frequency_df = pd.DataFrame(byte_distribution_dominant_byte_frequency_list, columns=['byte_distribution_dominant_byte_frequency'])
byte_distribution_byte_range_spread_df = pd.DataFrame(byte_distribution_byte_range_spread_list, columns=['byte_distribution_byte_range_spread'])
X_test = pd.concat([X_test, byte_value_histogram_mean_df, byte_value_histogram_std_dev_df, byte_distribution_entropy_df, byte_distribution_uniformity_score_df, byte_distribution_peak_to_mean_ratio_df, byte_distribution_low_frequency_byte_count_df, byte_distribution_skewness_df, byte_distribution_kurtosis_df, byte_distribution_dominant_byte_frequency_df, byte_distribution_byte_range_spread_df], axis=1)


X_test.drop(columns=['byte_value_histogram'], inplace=True)

import numpy as np
byte_value_25th_percentile_list = []
byte_value_50th_percentile_list = []
byte_value_75th_percentile_list = []
for i in X_test['byte_value_percentiles']:
    l = i.split(', ')
    l1 = []
    for j in l:
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        l1.append(float(j))
    byte_value_25th_percentile_list.append(l1[0])
    byte_value_50th_percentile_list.append(l1[1])
    byte_value_75th_percentile_list.append(l1[2])
byte_value_25th_percentile_df = pd.DataFrame(byte_value_25th_percentile_list, columns=['byte_value_25th_percentile'])
byte_value_50th_percentile_df = pd.DataFrame(byte_value_50th_percentile_list, columns=['byte_value_50th_percentile'])
byte_value_75th_percentile_df = pd.DataFrame(byte_value_75th_percentile_list, columns=['byte_value_75th_percentile'])
X_test = pd.concat([X_test, byte_value_25th_percentile_df, byte_value_50th_percentile_df, byte_value_75th_percentile_df], axis=1)


X_test.drop(columns='byte_value_percentiles', inplace=True)



import numpy as np
freq_byte_value_diff_mean_keys_list = []
freq_byte_value_diff_mean_values_list = []
freq_byte_value_diff_weighted_mean_list = []
freq_byte_value_diff_max_keys_list = []
freq_byte_value_diff_max_values_list = []
freq_byte_value_diff_std_dev_keys_list = []
for i in X_test['freq_byte_value_diff']:
    l = i.split(', ')
    d = {}
    for j in l:
        if (j[0] == '{'):
            j = j[1:]
        if (j[-1] == '}'):
            j = j[:-1]
        l1 = j.split(': ')
        d[int(l1[0])] = int(l1[1])
    freq_byte_value_diff_mean_keys_list.append(np.mean(list(d.keys())))
    freq_byte_value_diff_mean_values_list.append(np.mean(list(d.values())))
    freq_byte_value_diff_weighted_mean_list.append(np.average(list(d.keys()), weights=list(d.values())))
    freq_byte_value_diff_max_keys_list.append(max(list(d.keys())))
    freq_byte_value_diff_max_values_list.append(max(list(d.values())))
    freq_byte_value_diff_std_dev_keys_list.append(np.std(list(d.keys())))
freq_byte_value_diff_mean_keys_df = pd.DataFrame(freq_byte_value_diff_mean_keys_list, columns=['freq_byte_value_diff_mean_keys'])
freq_byte_value_diff_mean_values_df = pd.DataFrame(freq_byte_value_diff_mean_values_list, columns=['freq_byte_value_diff_mean_values'])
freq_byte_value_diff_weighted_mean_df = pd.DataFrame(freq_byte_value_diff_weighted_mean_list, columns=['freq_byte_value_diff_weighted_mean'])
freq_byte_value_diff_max_keys_df = pd.DataFrame(freq_byte_value_diff_max_keys_list, columns=['freq_byte_value_diff_max_keys'])
freq_byte_value_diff_max_values_df = pd.DataFrame(freq_byte_value_diff_max_values_list, columns=['freq_byte_value_diff_max_values'])
freq_byte_value_diff_std_dev_keys_df = pd.DataFrame(freq_byte_value_diff_std_dev_keys_list, columns=['freq_byte_value_diff_std_dev_keys'])
X_test = pd.concat([X_test, freq_byte_value_diff_mean_keys_df, freq_byte_value_diff_mean_values_df, freq_byte_value_diff_weighted_mean_df, freq_byte_value_diff_max_keys_df, freq_byte_value_diff_max_values_df, freq_byte_value_diff_std_dev_keys_df], axis=1)


X_test.drop(columns=['freq_byte_value_diff'], inplace=True)



import numpy as np
run_length_encoding_total_encoding_length_list = []
run_length_encoding_max_run_length_list = []
run_length_encoding_mean_run_length_list = []
run_length_encoding_std_dev_run_length_list = []
run_length_encoding_mean_value_list = []
run_length_encoding_std_dev_value_list = []
for i in X_test['run_length_encoding']:
    l = i.split(', ')
    run = []
    value = []
    parity = 0
    for j in l:
        if (j == ''):
            run.append(0)
            value.append(0)
            continue
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        if (parity == 0):
            j = j[1:]
            if ((len(j) > 1) and (j[-1] == ',')):
                j = j[:-1]
            if (j == ''):
                run.append(0)
            else:
                run.append(int(j))
            parity = 1
        else:
            j = j[:-1]
            if ((len(j) > 1) and (j[-1] == ',')):
                j = j[:-1]
            if (j == ''):
                value.append(0)
            else:
                if (j[-1] == ')'):
                    j = j[:-1]
                value.append(int(j))
            parity = 0
    run_length_encoding_total_encoding_length_list.append(sum(run))
    run_length_encoding_max_run_length_list.append(max(run))
    run_length_encoding_mean_run_length_list.append(np.mean(run))
    run_length_encoding_std_dev_run_length_list.append(np.std(run))
    run_length_encoding_mean_value_list.append(np.mean(value))
    run_length_encoding_std_dev_value_list.append(np.std(value))
run_length_encoding_total_encoding_length_df = pd.DataFrame(run_length_encoding_total_encoding_length_list, columns=['run_length_encoding_total_encoding_length'])
run_length_encoding_max_run_length_df = pd.DataFrame(run_length_encoding_max_run_length_list, columns=['run_length_encoding_max_run_length'])
run_length_encoding_mean_run_length_df = pd.DataFrame(run_length_encoding_mean_run_length_list, columns=['run_length_encoding_mean_run_length'])
run_length_encoding_std_dev_run_length_df = pd.DataFrame(run_length_encoding_std_dev_run_length_list, columns=['run_length_encoding_std_dev_run_length'])
run_length_encoding_mean_value_df = pd.DataFrame(run_length_encoding_mean_value_list, columns=['run_length_encoding_mean_value'])
run_length_encoding_std_dev_value_df = pd.DataFrame(run_length_encoding_std_dev_value_list, columns=['run_length_encoding_std_dev_value'])
X_test = pd.concat([X_test, run_length_encoding_total_encoding_length_df, run_length_encoding_max_run_length_df, run_length_encoding_mean_run_length_df, run_length_encoding_std_dev_run_length_df, run_length_encoding_mean_value_df, run_length_encoding_std_dev_value_df], axis=1)


X_test.drop(columns=['run_length_encoding'], inplace=True)


from scipy.stats import entropy
import numpy as np
byte_value_transition_matrix_sparsity_list = []
byte_value_transition_matrix_entropy_list = []
byte_value_transition_matrix_top_k_sum_list = []
byte_value_transition_matrix_mean_prob_per_row_list = []
byte_value_transition_matrix_quadrant_1_sum_list = []
byte_value_transition_matrix_quadrant_2_sum_list = []
byte_value_transition_matrix_quadrant_3_sum_list = []
byte_value_transition_matrix_quadrant_4_sum_list = []
for i in X_test['byte_value_transition_matrix']:
    l = []
    l1 = i.split(', ')
    l2 = []
    for j in l1:
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        if (j[0] == '['):
            j = j[1:]
        if (j[-1] == ']'):
            j = j[:-1]
        if ((len(j) > 1) and (j[-1] == ',')):
            j = j[:-1]
        if (type(j) == list):
            l.append(j)
        else:
            l2.append(int(j))
        if (len(l2) == 256):
            l1.append(l2)
            l2 = []
    l = np.array(l)
    sparsity = 1 - np.count_nonzero(l) / (256 * 256)
    byte_value_transition_matrix_sparsity_list.append(sparsity)
    prob_matrix = l / np.sum(l)
    byte_value_transition_matrix_entropy_list.append(entropy(prob_matrix.flatten(), base=2))
    top_k_transitions = np.sort(l.flatten())[::-1][:5]  # Sum of top 5
    top_k_sum = np.sum(top_k_transitions)
    byte_value_transition_matrix_top_k_sum_list.append(top_k_sum)
    normalized_matrix = l / (np.sum(l, axis=1, keepdims=True) + 1e-10)
    byte_value_transition_matrix_mean_prob_per_row_list.append(np.mean(normalized_matrix, axis=1).mean())
    byte_value_transition_matrix_quadrant_1_sum_list.append(np.sum(l[:128, :128]))  # Top-left
    byte_value_transition_matrix_quadrant_2_sum_list.append(np.sum(l[:128, 128:]))  # Top-right
    byte_value_transition_matrix_quadrant_3_sum_list.append(np.sum(l[128:, :128]))  # Bottom-left
    byte_value_transition_matrix_quadrant_4_sum_list.append(np.sum(l[128:, 128:]))  # Bottom-right
byte_value_transition_matrix_sparsity_df = pd.DataFrame(byte_value_transition_matrix_sparsity_list, columns=['byte_value_transition_matrix_sparsity'])
byte_value_transition_matrix_entropy_df = pd.DataFrame(byte_value_transition_matrix_entropy_list, columns=['byte_value_transition_matrix_entropy'])
byte_value_transition_matrix_top_k_sum_df = pd.DataFrame(byte_value_transition_matrix_top_k_sum_list, columns=['byte_value_transition_matrix_top_k_sum'])
byte_value_transition_matrix_mean_prob_per_row_df = pd.DataFrame(byte_value_transition_matrix_mean_prob_per_row_list, columns=['byte_value_transition_matrix_mean_prob_per_row'])
byte_value_transition_matrix_quadrant_1_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_1_sum_list, columns=['byte_value_transition_matrix_quadrant_1_sum'])
byte_value_transition_matrix_quadrant_2_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_2_sum_list, columns=['byte_value_transition_matrix_quadrant_2_sum'])
byte_value_transition_matrix_quadrant_3_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_3_sum_list, columns=['byte_value_transition_matrix_quadrant_3_sum'])
byte_value_transition_matrix_quadrant_4_sum_df = pd.DataFrame(byte_value_transition_matrix_quadrant_4_sum_list, columns=['byte_value_transition_matrix_quadrant_4_sum'])
X_test = pd.concat([X_test, byte_value_transition_matrix_sparsity_df, byte_value_transition_matrix_entropy_df, byte_value_transition_matrix_top_k_sum_df, byte_value_transition_matrix_mean_prob_per_row_df, byte_value_transition_matrix_quadrant_1_sum_df, byte_value_transition_matrix_quadrant_2_sum_df, byte_value_transition_matrix_quadrant_3_sum_df, byte_value_transition_matrix_quadrant_4_sum_df], axis=1)


X_test.drop(columns=['byte_value_transition_matrix'], inplace=True)



X_test.drop(columns=['freq_byte_value_2grams', 'freq_byte_value_3grams', 'freq_byte_value_4grams'], inplace=True)



import numpy as np
import pandas as pd
import ast

# Function to summarize ACF for a single ciphertext
def summarize_acf(acf_values):
    # Ensure the input is a list of floats
    acf_values = np.array(acf_values, dtype=np.float64)

    # Exclude lag 0 (self-correlation)
    acf_no_lag0 = acf_values[1:]

    # Compute features
    mean_acf = np.mean(acf_no_lag0)
    variance_acf = np.var(acf_no_lag0)
    max_acf = np.max(acf_no_lag0)
    lag_of_max_acf = np.argmax(acf_no_lag0) + 1  # +1 because we excluded lag 0

    return {
        "mean_acf": mean_acf,
        "variance_acf": variance_acf,
        "max_acf": max_acf,
        "lag_of_max_acf": lag_of_max_acf
    }



# Convert the string representation of a list into an actual list
X_test['byte_value_acf'] = X_test['byte_value_acf'].apply(lambda x: ast.literal_eval(x))

# Apply summarize_acf for each row in 'byte_value_acf' column
features_list = X_test['byte_value_acf'].apply(summarize_acf)

# Convert features_list into a DataFrame
features_df = pd.DataFrame(features_list.tolist())

# Add the new features to the original X_train
X_test = pd.concat([X_test, features_df], axis=1)

# Print the updated X_train with extracted features


X_test.drop(columns=['byte_value_acf'], inplace=True)



import numpy as np
import pandas as pd

# Function to calculate total power (sum of all frequencies)
def total_power(power_spectrum):
    return np.sum(power_spectrum)

# Function to calculate peak power (maximum frequency component)
def peak_power(power_spectrum):
    return np.max(power_spectrum)

# Function to calculate power concentration (ratio of top n frequencies' power to total power)
def power_concentration(power_spectrum, top_n=3):
    sorted_spectrum = np.sort(power_spectrum)[::-1]  # Sort in descending order
    return np.sum(sorted_spectrum[:top_n]) / np.sum(power_spectrum)

# # Example of applying these functions to your data
# X_train = pd.DataFrame({
#     'byte_value_power_spectrum': [
#         [150100455184.0, 10933011.937147308, 17569885.488023052],
#         [60031504.0, 400436.77105714486, 428221.7924971855],
#         [11758041.0, 98795.90679018006, 258054.280108135],
#         [3150625.0, 36711.263661699806, 240051.794852449],
#         [619369.0, 18911.38498657157, 91709.0000000000]
#     ]
# })

l = []
for i in X_test['byte_value_power_spectrum']:
    l1 = []
    l2 = i.split(", ")
    for j in l2:
      if (j == ''):
          l1.append(0)
          continue
      if (j[0] == '['):
          j = j[1:]
      if (j[-1] == ']'):
          j = j[:-1]
      if (j[-1] == ','):
          j = j[:-1]
      l1.append(float(j))
    l.append(l1)
X_test['byte_value_power_spectrum'] = l

# Apply the functions to each row in the 'byte_value_power_spectrum' column
X_test['total_power'] = X_test['byte_value_power_spectrum'].apply(lambda x: total_power(x))
X_test['peak_power'] = X_test['byte_value_power_spectrum'].apply(lambda x: peak_power(x))
X_test['power_concentration'] = X_test['byte_value_power_spectrum'].apply(lambda x: power_concentration(x))



X_test.drop(columns=['byte_value_power_spectrum'], inplace=True)



# columns = []
# for i in X_test:
#     if X_test[i].dtype == 'object':
#         columns.append(i)
# X_test.drop(columns=columns, inplace=True)
# X_test

"""##Imputing Null Values for Testing Dataset"""



X_test['byte_value_transition_matrix_entropy'] = imputer.transform(X_test[['byte_value_transition_matrix_entropy']])




import numpy as np
from sklearn.impute import SimpleImputer

imputer_sc = SimpleImputer(missing_values=np.nan, strategy='median')
X_test['serial_correlation'] = imputer_sc.fit_transform(X_test[['serial_correlation']])

from sklearn.model_selection import train_test_split

X_val, X_test_final, y_val, y_test_final = train_test_split(X_test, y_test, test_size=0.5, random_state=42)
X_test = X_test_final
y_test = y_test_final

"""##Exporting Final X_test and y_test Without Normalization"""



"""##Extracting Testing Dataset for CNN"""

X_test_cnn = X_test
y_test_cnn = y_test

"""##Normalization of Testing Dataset"""

exclude_columns = ['mode', 'block_size', 'block_cipher_boolean', 'block_frequency', 'length', 'byte_distribution_uniformity_score', 'byte_distribution_low_frequency_byte_count', 'byte_distribution_skewness', 'byte_distribution_kurtosis', 'byte_distribution_dominant_byte_frequency', 'byte_distribution_byte_range_spread']
columns_to_scale = X_test.columns.difference(exclude_columns)
X_test[columns_to_scale] = scaler.transform(X_test[columns_to_scale])

X_val_cnn = X_val
y_val_cnn = y_val

exclude_columns = ['mode', 'block_size', 'block_cipher_boolean', 'block_frequency', 'length', 'byte_distribution_uniformity_score', 'byte_distribution_low_frequency_byte_count', 'byte_distribution_skewness', 'byte_distribution_kurtosis', 'byte_distribution_dominant_byte_frequency', 'byte_distribution_byte_range_spread']
columns_to_scale = X_val.columns.difference(exclude_columns)
X_val[columns_to_scale] = scaler.transform(X_val[columns_to_scale])

#XGBoost

# Importing necessary libraries
import xgboost as xgb
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder



# Initialize the XGBoost model for multi-class classification
xgb_model = xgb.XGBClassifier(
    objective='multi:softmax',  # Multi-class classification
    num_class=10,               # Number of classes (14 in your case)
    eval_metric='mlogloss'      # Multi-class log loss metric
)

label_encoder_xgboost = LabelEncoder()
# Fit and transform the target variables to numerical values
y_train_encoded = label_encoder_xgboost.fit_transform(y_train)
y_val_encoded = label_encoder_xgboost.transform(y_val)
y_test_encoded = label_encoder_xgboost.transform(y_test)

# Fit the model on the training data
xgb_model.fit(X_train, y_train_encoded)

# # Make predictions on the validation set
# y_pred_xgb_encoded = xgb_model.predict(X_val)

# # Evaluate the model
# accuracy = accuracy_score(y_val_encoded, y_pred_xgb_encoded)
# print(f"Accuracy: {accuracy * 100:.2f}%")
# y_pred_xgb = label_encoder_xgboost.inverse_transform(y_pred_xgb_encoded)
# # Print detailed classification report
# print(classification_report(y_val, y_pred_xgb))

node_features_xgb_training = xgb_model.predict_proba(X_train)
node_features_xgb_validation = xgb_model.predict_proba(X_val)
node_features_xgb_testing = xgb_model.predict_proba(X_test)

def xgb_model_function():
    return xgb_model

#Randomforest
from sklearn.ensemble import RandomForestClassifier
# Initialize Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the model
rf_model.fit(X_train, y_train)

# # Make predictions
# y_pred = rf_model.predict(X_val)
# # print(y_pred)

# # Evaluate the model
# accuracy = accuracy_score(y_val, y_pred)
# print(f"Accuracy: {accuracy * 100:.2f}%")

# # Print detailed classification report
# print(classification_report(y_val, y_pred))

node_features_rf_training = rf_model.predict_proba(X_train)
node_features_rf_validation = rf_model.predict_proba(X_val)
node_features_rf_testing = rf_model.predict_proba(X_test)

def rf_model_function():
    return rf_model

#Heirarchical Model 1

from sklearn.preprocessing import LabelEncoder
label_encoder_hierarchial_rf = LabelEncoder()
y_train_encoded_hierarchial_rf = label_encoder_hierarchial_rf.fit_transform(y_train)
# y_val_encoded_hierarchial_rf = label_encoder_hierarchial_rf.transform(y_val)

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from itertools import combinations
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Step 1: Train the first Random Forest model for top-3 prediction
def train_top3_model_1(X_train, y_train_encoded_hierarchial_rf):
    model_top3 = RandomForestClassifier(random_state=42)
    model_top3.fit(X_train, y_train_encoded_hierarchial_rf)
    return model_top3

# Step 2: Create and train models for all combinations of top-3 classes
def train_combination_models_1(X_train, y_train_encoded_hierarchial_rf, all_classes):
    combination_models = {}
    count = 0
    for combination in combinations(all_classes, 3):
        # Filter the dataset for the current combination
        mask = pd.Series(y_train_encoded_hierarchial_rf).isin(combination)
        X_subset = pd.DataFrame(X_train[mask], columns=X_train.columns)
        # print(X_subset)
        # break
        # print(X_subset)
        y_subset = y_train_encoded_hierarchial_rf[mask]
        count = count + 1
        print(count)
        if (X_subset.shape[0] != 0):
            # Train a RandomForestClassifier for this combination
            model = RandomForestClassifier(random_state=42)
            model.fit(X_subset, y_subset)
            combination_models[combination] = model
    return combination_models

# Step 3: Top-3 prediction and refinement
def predict_with_top3_model_1(X_val, model_top3, combination_models, all_classes):
    # Step 3.1: Predict top-3 classes using model_top4
    probs = model_top3.predict_proba(X_val)
    top3_predictions = np.argsort(probs, axis=1)[:, -3:]  # Indices of top-3 classes

    final_predictions = []
    for i in range(len(X_val)):
        # Step 3.2: Get the actual top-3 class labels
        top3_classes = [all_classes[j] for j in top3_predictions[i]]
        top3_classes_tuple = tuple(sorted(top3_classes))  # Match the order in combination_models

        # Step 3.3: Use the corresponding combination model
        if top3_classes_tuple in combination_models:
            model = combination_models[top3_classes_tuple]
            final_predictions.append(model.predict(pd.DataFrame([X_val.iloc[i]], columns=X_test.columns))[0])
        else:
            # If no specific model is available, default to the top-3 class with highest probability
            final_predictions.append(top3_classes[-1])  # Most likely class
    return final_predictions

all_classes = sorted(list(set(y_train_encoded_hierarchial_rf)))  # Unique classes (14 in this case)

# Train the top-3 model
model_top3_1 = train_top3_model_1(X_train, y_train_encoded_hierarchial_rf)

# Train combination models
combination_models_1 = train_combination_models_1(X_train, y_train_encoded_hierarchial_rf, all_classes)

# # Predict on test set
# final_predictions = predict_with_top3_model_1(X_val, model_top3_1, combination_models_1, all_classes)
# print("Final predictions:", final_predictions)
# print(classification_report(y_val_encoded_hierarchial_rf, final_predictions))
# # Calculate accuracy
# accuracy = accuracy_score(y_val_encoded_hierarchial_rf, final_predictions)
# print(f"Accuracy: {accuracy * 100:.2f}")  # Outputs accuracy as a percentage

mapping = {'3DES': 0, 'AES': 1, 'ChaCha20': 2, 'ECC': 3, 'ECDSA': 4, 'HMAC': 5, 'MD5': 6, 'RSA': 7, 'Rabbit': 8, 'SHA3': 9}

# Step 3: Top-3 prediction and refinement
def probabilities_hm_1(X_val, model_top3, combination_models, all_classes):
    # Step 3.1: Predict top-3 classes using model_top4
    probs = model_top3.predict_proba(X_val)
    top3_predictions = np.argsort(probs, axis=1)[:, -3:]  # Indices of top-3 classes

    probabilities = []
    for i in range(len(X_val)):
        # Step 3.2: Get the actual top-3 class labels
        top3_classes = [all_classes[j] for j in top3_predictions[i]]
        top3_classes_tuple = tuple(sorted(top3_classes))  # Match the order in combination_models

        # Step 3.3: Use the corresponding combination model
        if top3_classes_tuple in combination_models:
            model = combination_models[top3_classes_tuple]
            probabilities1 = model.predict_proba(pd.DataFrame([X_val.iloc[i]], columns=X_test.columns))
            # print(probabilities1[0][0])
            classes = model.classes_
            classes = label_encoder_hierarchial_rf.inverse_transform(classes)
            probabilities2 = [0, 0, 0, 0, 0, 0, 0]
            for j in range(0, len(classes)):
                index = mapping[classes[j]]
                if (index >= len(probabilities2)):
                    probabilities2.append(probabilities1[0][j])
                else:
                    probabilities2.insert(index, probabilities1[0][j])
        else:
            # If no specific model is available, default to the top-3 class with highest probability
            probabilities2 = [0, 0, 0, 0, 0, 0, 0, 0, 0]
            classes = [top3_classes[-1]]
            classes = label_encoder_hierarchial_rf.inverse_transform(classes)
            probabilities2.insert(mapping[classes[0]], 1)
        probabilities.append(probabilities2)
    return probabilities

nodes_features_hm_1_training = probabilities_hm_1(X_train, model_top3_1, combination_models_1, all_classes)
nodes_features_hm_1_validation = probabilities_hm_1(X_val, model_top3_1, combination_models_1, all_classes)
nodes_features_hm_1_testing = probabilities_hm_1(X_test, model_top3_1, combination_models_1, all_classes)

nodes_features_hm_1_training1 = np.array(nodes_features_hm_1_training)
nodes_features_hm_1_validation1 = np.array(nodes_features_hm_1_validation)
nodes_features_hm_1_testing1 = np.array(nodes_features_hm_1_testing)

def model_top3_1_function():
    return model_top3_1

def combination_models_1_function():
    return combination_models_1

def probabilities_hm_1_function():
    return probabilities_hm_1

def all_classes_function():
    return all_classes

#Heirchical Model 3

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from itertools import combinations
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.neural_network import MLPClassifier

# Step 1: Train the first Random Forest model for top-3 prediction
def train_top3_model_3(X_train, y_train_encoded_hierarchial_rf):
    model_top3 = RandomForestClassifier(random_state=42)
    model_top3.fit(X_train, y_train_encoded_hierarchial_rf)
    return model_top3

# Step 2: Create and train models for all combinations of top-3 classes
def train_combination_models_3(X_train, y_train_encoded_hierarchial_rf, all_classes):
    combination_models = {}
    count = 0
    for combination in combinations(all_classes, 3):
        # Filter the dataset for the current combination
        mask = pd.Series(y_train_encoded_hierarchial_rf).isin(combination)
        X_subset = pd.DataFrame(X_train[mask], columns=X_train.columns)
        # print(X_subset)
        # break
        # print(X_subset)
        y_subset = y_train_encoded_hierarchial_rf[mask]
        count = count + 1
        print(count)
        if (X_subset.shape[0] != 0):
            # Define the Neural Network (MLPClassifier)
            mlp_model = MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=500, early_stopping=True, random_state=42, activation='relu', solver='adam')
            mlp_model.fit(X_subset, y_subset)
            combination_models[combination] = mlp_model
    return combination_models

# Step 3: Top-3 prediction and refinement
def predict_with_top3_model_3(X_val, model_top3, combination_models, all_classes):
    # Step 3.1: Predict top-3 classes using model_top4
    probs = model_top3.predict_proba(X_val)
    top3_predictions = np.argsort(probs, axis=1)[:, -3:]  # Indices of top-3 classes

    final_predictions = []
    for i in range(len(X_val)):
        # Step 3.2: Get the actual top-3 class labels
        top3_classes = [all_classes[j] for j in top3_predictions[i]]
        top3_classes_tuple = tuple(sorted(top3_classes))  # Match the order in combination_models

        # Step 3.3: Use the corresponding combination model
        if top3_classes_tuple in combination_models:
            mlp_model = combination_models[top3_classes_tuple]
            final_predictions.append(mlp_model.predict(pd.DataFrame([X_val.iloc[i]], columns=X_val.columns))[0])
        else:
            # If no specific model is available, default to the top-3 class with highest probability
            final_predictions.append(top3_classes[-1])  # Most likely class
    return final_predictions

all_classes = sorted(list(set(y_train_encoded_hierarchial_rf)))  # Unique classes (14 in this case)

# Train the top-3 model
model_top3_3 = train_top3_model_3(X_train, y_train_encoded_hierarchial_rf)

# Train combination models
combination_models_3 = train_combination_models_3(X_train, y_train_encoded_hierarchial_rf, all_classes)

# # Predict on test set
# final_predictions = predict_with_top3_model_3(X_val, model_top3_3, combination_models_3, all_classes)
# print("Final predictions:", final_predictions)
# print(classification_report(y_val_encoded_hierarchial_rf, final_predictions))
# # Calculate accuracy
# accuracy = accuracy_score(y_val_encoded_hierarchial_rf, final_predictions)
# print(f"Accuracy: {accuracy * 100:.2f}")  # Outputs accuracy as a percentage

# Step 3: Top-3 prediction and refinement
def probabilities_hm_3(X_val, model_top3, combination_models, all_classes):
    # Step 3.1: Predict top-3 classes using model_top4
    probs = model_top3.predict_proba(X_val)
    top3_predictions = np.argsort(probs, axis=1)[:, -3:]  # Indices of top-3 classes

    probabilities = []
    for i in range(len(X_val)):
        # Step 3.2: Get the actual top-3 class labels
        top3_classes = [all_classes[j] for j in top3_predictions[i]]
        top3_classes_tuple = tuple(sorted(top3_classes))  # Match the order in combination_models

        # Step 3.3: Use the corresponding combination model
        if top3_classes_tuple in combination_models:
            model = combination_models[top3_classes_tuple]
            probabilities1 = model.predict_proba(pd.DataFrame([X_val.iloc[i]], columns=X_test.columns))
            # print(probabilities1[0][0])
            classes = model.classes_
            classes = label_encoder_hierarchial_rf.inverse_transform(classes)
            probabilities2 = [0, 0, 0, 0, 0, 0, 0]
            for j in range(0, len(classes)):
                index = mapping[classes[j]]
                if (index >= len(probabilities2)):
                    probabilities2.append(probabilities1[0][j])
                else:
                    probabilities2.insert(index, probabilities1[0][j])
        else:
            # If no specific model is available, default to the top-3 class with highest probability
            probabilities2 = [0, 0, 0, 0, 0, 0, 0, 0, 0]
            classes = [top3_classes[-1]]
            classes = label_encoder_hierarchial_rf.inverse_transform(classes)
            probabilities2.insert(mapping[classes[0]], 1)
        probabilities.append(probabilities2)
    return probabilities

nodes_features_hm_3_training = probabilities_hm_3(X_train, model_top3_3, combination_models_3, all_classes)
nodes_features_hm_3_validation = probabilities_hm_3(X_val, model_top3_3, combination_models_3, all_classes)
nodes_features_hm_3_testing = probabilities_hm_3(X_test, model_top3_3, combination_models_3, all_classes)

nodes_features_hm_3_training1 = np.array(nodes_features_hm_3_training)
nodes_features_hm_3_validation1 = np.array(nodes_features_hm_3_validation)
nodes_features_hm_3_testing1 = np.array(nodes_features_hm_3_testing)

def model_top3_3_function():
    return model_top3_3

def combination_models_3_function():
    return combination_models_3

def probabilities_hm_3_function():
    return probabilities_hm_3

#Neural Network

label_encoder2 = LabelEncoder()
label_encoder2.fit(y_train)
y_train_neural_network = label_encoder2.transform(y_train)
y_val_neural_network = label_encoder2.transform(y_val)
def label_encoder_nn_function():
    return label_encoder2


"""##**Neural Network Model**"""

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

nn_model = Sequential()
nn_model.add(Dense(32, input_dim=106, activation='relu'))
nn_model.add(Dense(16, activation='relu'))  # Hidden layer
num_classes = len(label_encoder2.classes_)
nn_model.add(Dense(num_classes, activation='softmax'))  # Output layer for binary classification

nn_model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

nn_model.fit(X_train, y_train_neural_network, epochs=50, batch_size=10, validation_data=(X_val, y_val_neural_network))

node_features_nn_training = nn_model.predict(X_train)
node_features_nn_validation = nn_model.predict(X_val)
node_features_nn_testing = nn_model.predict(X_test)

def nn_model_function():
    return nn_model

#Convolutional Neural Network(Model 1)

import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import matplotlib.pyplot as plt
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense
import os

# Step 1: Manually load or upload the CSV files
# Uncomment the next line if you're using Google Colab for file uploading
# uploaded = files.upload()

# # Step 2: Read the data from the separate CSV files (assuming you have uploaded them)
# X_train = pd.read_csv('X_train.csv').values  # Load X_train from the first CSV file
# y_train = pd.read_csv('y_train.csv').values  # Load Y_train from the second CSV file
# X_test = pd.read_csv('X_test.csv').values
# y_test = pd.read_csv('y_test.csv').values

# # Step 3: Check the shapes of X_train and Y_train
# print("X_train shape:", X_train_cnn.shape)
# print("y_train shape:", y_train_cnn.shape)

# # Ensure X_train and Y_train have the same number of rows (samples)
# if (X_train.shape[0] != y_train.shape[0]):
#     print(f"Warning: Mismatch in number of samples. X_train has {X_train.shape[0]} samples and Y_train has {Y_train.shape[0]} samples.")
#     # Optionally, you can crop the larger dataset to match the smaller one
    # min_samples = min(X_train.shape[0], y_train.shape[0])
    # X_train = X_train[:min_samples]
    # y_train = y_train[:min_samples]

# Step 4: Normalize/standardize the feature data
scaler_cnn = MinMaxScaler()
X_train_normalized_cnn = scaler_cnn.fit_transform(X_train_cnn)

# Step 5: Convert Y_train (if it's categorical) into numeric labels
y_train_cnn = y_train_cnn.astype(str)
label_encoder_cnn = LabelEncoder()
# y_train_cnn = y_train_cnn.flatten()
# y_train_cnn = [y_train_cnn[i] for i in range(0, 2 * X_train_cnn.shape[0]) if (i % 2) == 1]
# print(y_train_cnn)
# print(len(y_train_cnn))
y_train_encoded_cnn = label_encoder_cnn.fit_transform(y_train_cnn)
# y_train_encoded = y_train_encoded[1]

# Step 6: Reshape X_train into 10x11 images
n_samples, n_features = X_train_normalized_cnn.shape
n_rows = 10
n_cols = 11  # We now have 110 features after padding

# Pad if necessary (ensure 110 features)
if n_features < n_rows * n_cols:
    padding = n_rows * n_cols - n_features
    X_train_normalized_cnn = np.pad(X_train_normalized_cnn, ((0, 0), (0, padding)), mode='constant', constant_values=0)

X_train_images = X_train_normalized_cnn.reshape(n_samples, n_rows, n_cols, 1)

# # Verify the shape of reshaped data
# print("X_train reshaped shape:", X_train_images.shape)

# # Step 7: Create a directory to save the images
# output_dir = 'output_images/train'
# os.makedirs(output_dir, exist_ok=True)

# # Step 8: Save each image as a PNG file
# for i in range(n_samples):
#     img = X_train_images[i].reshape(n_rows, n_cols)  # Reshape to 10x11 for visualization
#     plt.imshow(img, cmap='gray', interpolation='nearest')  # Display image in grayscale
#     plt.axis('off')  # Turn off axis
#     plt.savefig(f"{output_dir}/image_{i}.png", bbox_inches='tight', pad_inches=0)
#     plt.close()  # Close the plot to avoid display
#     if (i == 5):
#         break

# print(f"Images saved in {output_dir} directory.")

X_val_normalized_cnn = scaler_cnn.transform(X_val_cnn)
y_val_cnn = y_val_cnn.astype(str)
# y_test = y_test.flatten()
# y_test = [y_test[i] for i in range(0, 2 * X_test.shape[0]) if (i % 2) == 1]
# print(y_val_cnn)
# print(len(y_val_cnn))
y_val_encoded_cnn = label_encoder_cnn.transform(y_val_cnn)
# y_test_encoded = y_test_encoded[1]
# Step 6: Reshape X_train into 10x11 images
n_samples, n_features = X_val_normalized_cnn.shape
n_rows = 10
n_cols = 11  # We now have 110 features after padding
# Pad if necessary (ensure 110 features)
if n_features < n_rows * n_cols:
    padding = n_rows * n_cols - n_features
    X_val_normalized_cnn = np.pad(X_val_normalized_cnn, ((0, 0), (0, padding)), mode='constant', constant_values=0)
X_val_images = X_val_normalized_cnn.reshape(n_samples, n_rows, n_cols, 1)

# # Verify the shape of reshaped data
# print("X_test reshaped shape:", X_val_images.shape)

# # Step 7: Create a directory to save the images
# output_dir = 'output_images/test'
# os.makedirs(output_dir, exist_ok=True)

# # Step 8: Save each image as a PNG file
# for i in range(n_samples):
#     img = X_val_images[i].reshape(n_rows, n_cols)  # Reshape to 10x11 for visualization
#     plt.imshow(img, cmap='gray', interpolation='nearest')  # Display image in grayscale
#     plt.axis('off')  # Turn off axis
#     plt.savefig(f"{output_dir}/image_{i}.png", bbox_inches='tight', pad_inches=0)
#     plt.close()  # Close the plot to avoid display
#     if (i == 5):
#         break

X_test_normalized_cnn = scaler_cnn.transform(X_test_cnn)
# y_test_cnn = y_test_cnn.astype(str)
# y_test = y_test.flatten()
# y_test = [y_test[i] for i in range(0, 2 * X_test.shape[0]) if (i % 2) == 1]
# print(y_val_cnn)
# print(len(y_val_cnn))
# y_val_encoded_cnn = encoder.transform(y_val_cnn)
# y_test_encoded = y_test_encoded[1]
# Step 6: Reshape X_train into 10x11 images
n_samples, n_features = X_test_normalized_cnn.shape
n_rows = 10
n_cols = 11  # We now have 110 features after padding
# Pad if necessary (ensure 110 features)
if n_features < n_rows * n_cols:
    padding = n_rows * n_cols - n_features
    X_test_normalized_cnn = np.pad(X_test_normalized_cnn, ((0, 0), (0, padding)), mode='constant', constant_values=0)
X_test_images = X_test_normalized_cnn.reshape(n_samples, n_rows, n_cols, 1)

# # Verify the shape of reshaped data
# print("X_test reshaped shape:", X_test_images.shape)

# # Step 7: Create a directory to save the images
# output_dir = 'output_images/test'
# os.makedirs(output_dir, exist_ok=True)

# # Step 8: Save each image as a PNG file
# for i in range(n_samples):
#     img = X_test_images[i].reshape(n_rows, n_cols)  # Reshape to 10x11 for visualization
#     plt.imshow(img, cmap='gray', interpolation='nearest')  # Display image in grayscale
#     plt.axis('off')  # Turn off axis
#     plt.savefig(f"{output_dir}/image_{i}.png", bbox_inches='tight', pad_inches=0)
#     plt.close()  # Close the plot to avoid display
#     if (i == 5):
#         break

# print(f"Images saved in {output_dir} directory.")

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras.utils import to_categorical
y_train_encoded_cnn_array = np.array(y_train_encoded_cnn)
y_val_encoded_cnn_array = np.array(y_val_encoded_cnn)
y_train_encoded_cnn_array_one_hot = to_categorical(y_train_encoded_cnn_array, num_classes=10)
y_val_encoded_cnn_array_one_hot = to_categorical(y_val_encoded_cnn_array, num_classes=10)
# Define the CNN model
def build_cnn(input_shape, num_classes):
    model = Sequential([
        # Convolutional Layer 1
        Conv2D(32, kernel_size=(3, 3), activation='relu', input_shape=input_shape),
        BatchNormalization(),
        MaxPooling2D(pool_size=(2, 2)),

        # Convolutional Layer 2
        Conv2D(64, kernel_size=(3, 3), activation='relu'),
        BatchNormalization(),
        MaxPooling2D(pool_size=(2, 2)),

        # Flatten the output and add Dense layers
        Flatten(),
        Dense(128, activation='relu'),
        Dropout(0.5),  # Regularization

        # Output Layer
        Dense(num_classes, activation='softmax')  # Softmax for multi-class classification
    ])
    return model

# Parameters
input_shape = (10, 11, 1)  # Assuming images are 11x10 with 1 channel
num_classes = 10           # Number of output classes
batch_size = 32            # Training batch size
epochs = 32                # Number of epochs

# Build the model
cnn_model = build_cnn(input_shape, num_classes)
cnn_model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])

# Train the model
history = cnn_model.fit(
    X_train_images, y_train_encoded_cnn_array_one_hot,
    validation_data=(X_val_images, y_val_encoded_cnn_array_one_hot),
    batch_size=batch_size,
    epochs=epochs,
    verbose=1
)
# # Step 5: Build the CNN model
# model = Sequential()

# # First convolutional layer with a smaller kernel size to avoid downsampling issues
# model.add(Conv2D(32, (3, 1), activation='relu', input_shape=(10, 11, 1)))  # Adjust input shape if needed
# model.add(MaxPooling2D((2, 1)))  # Adjust pool size to avoid downsampling issues

# # Second convolutional layer with a smaller kernel size
# model.add(Conv2D(64, (3, 1), activation='relu'))
# model.add(MaxPooling2D((2, 1)))  # Adjust pool size to avoid downsampling issues

# # Flatten the output for the fully connected layers
# model.add(Flatten())

# # Fully connected layer
# model.add(Dense(128, activation='relu'))

# # Output layer (using softmax for multi-class classification)
# model.add(Dense(14, activation='softmax'))

# # Step 6: Compile the model
# model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# # Step 7: Train the model
# history = model.fit(X_train_images, y_train_encoded, epochs=10, batch_size=32, validation_data=(X_test_images, y_test_encoded))

# # Step 8: Evaluate the model on the validation set
# loss, accuracy = cnn_model.evaluate(X_val_images, y_val_encoded_cnn_array_one_hot)
# print(f"Accuracy: {accuracy}")

# # Step 9: Plot the training and validation accuracy/loss
# plt.plot(history.history['accuracy'], label='train accuracy')
# plt.plot(history.history['val_accuracy'], label='val accuracy')
# plt.xlabel('Epoch')
# plt.ylabel('Accuracy')
# plt.legend()
# plt.title('Training and Validation Accuracy')
# plt.show()

# plt.plot(history.history['loss'], label='train loss')
# plt.plot(history.history['val_loss'], label='val loss')
# plt.xlabel('Epoch')
# plt.ylabel('Loss')
# plt.legend()
# plt.title('Training and Validation Loss')
# plt.show()

# print(f"Images saved in {output_dir} directory.")

node_features_cnn_training = cnn_model.predict(X_train_images)
node_features_cnn_validation = cnn_model.predict(X_val_images)
node_features_cnn_testing = cnn_model.predict(X_test_images)

def cnn_model_function():
    return cnn_model

def scaler_cnn_function():
    return scaler_cnn

node_features_training = []
batch_training = []
for i in range(0, len(X_train)):
    node_features_training.append(node_features_xgb_training[i])
    batch_training.append(i)
    node_features_training.append(node_features_rf_training[i])
    batch_training.append(i)
    node_features_training.append(nodes_features_hm_1_training[i])
    batch_training.append(i)
    node_features_training.append(nodes_features_hm_3_training[i])
    batch_training.append(i)
    node_features_training.append(node_features_nn_training[i])
    batch_training.append(i)
    node_features_training.append(node_features_cnn_training[i])
    batch_training.append(i)

node_features_validation = []
batch_validation = []
for i in range(0, len(X_val)):
    node_features_validation.append(node_features_xgb_validation[i])
    batch_validation.append(i)
    node_features_validation.append(node_features_rf_validation[i])
    batch_validation.append(i)
    node_features_validation.append(nodes_features_hm_1_validation[i])
    batch_validation.append(i)
    node_features_validation.append(nodes_features_hm_3_validation[i])
    batch_validation.append(i)
    node_features_validation.append(node_features_nn_validation[i])
    batch_validation.append(i)
    node_features_validation.append(node_features_cnn_validation[i])
    batch_validation.append(i)

node_features_testing = []
batch_testing = []
for i in range(0, len(X_test)):
    node_features_testing.append(node_features_xgb_testing[i])
    batch_testing.append(i)
    node_features_testing.append(node_features_rf_testing[i])
    batch_testing.append(i)
    node_features_testing.append(nodes_features_hm_1_testing[i])
    batch_testing.append(i)
    node_features_testing.append(nodes_features_hm_3_testing[i])
    batch_testing.append(i)
    node_features_testing.append(node_features_nn_testing[i])
    batch_testing.append(i)
    node_features_testing.append(node_features_cnn_testing[i])
    batch_testing.append(i)

from sklearn.preprocessing import LabelEncoder

label_encoder_integrated = LabelEncoder()
labels_training = label_encoder_integrated.fit_transform(y_train)
labels_validation = label_encoder_integrated.transform(y_val)
labels_testing = label_encoder_integrated.transform(y_test)

def label_encoder_integrated_function():
    return label_encoder_integrated

import torch

node_features_training_array = np.array(node_features_training)
node_features_training_tensor = torch.tensor(node_features_training_array, dtype=torch.float32)
batch_training_tensor = torch.tensor(batch_training, dtype=torch.long)
labels_training_tensor = torch.tensor(labels_training, dtype=torch.long)

node_features_validation_array = np.array(node_features_validation)
node_features_validation_tensor = torch.tensor(node_features_validation_array, dtype=torch.float32)
batch_validation_tensor = torch.tensor(batch_validation, dtype=torch.long)
labels_validation_tensor = torch.tensor(labels_validation, dtype=torch.long)

node_features_testing_array = np.array(node_features_testing)
node_features_testing_tensor = torch.tensor(node_features_testing_array, dtype=torch.float32)
batch_testing_tensor = torch.tensor(batch_testing, dtype=torch.long)
labels_testing_tensor = torch.tensor(labels_testing, dtype=torch.long)

import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv, global_mean_pool

torch.manual_seed(42)

# Define the GNN model for combining outputs from multiple models
class GNN(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim):
        super(GNN, self).__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.batch_norm1 = torch.nn.BatchNorm1d(hidden_dim)
        self.batch_norm2 = torch.nn.BatchNorm1d(hidden_dim)
        self.fc1 = torch.nn.Linear(hidden_dim, hidden_dim // 2)
        self.fc2 = torch.nn.Linear(hidden_dim // 2, output_dim)
        self.dropout = torch.nn.Dropout(0.3)

    def forward(self, x, edge_index, batch):
        # Graph convolutional layers
        x = F.relu(self.conv1(x, edge_index))
        x = self.batch_norm1(x)
        x = F.relu(self.conv2(x, edge_index))
        x = self.batch_norm2(x)

        # Global pooling and fully connected layers
        x = global_mean_pool(x, batch)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)

        return F.log_softmax(x, dim=1)


# Create a fully connected edge index for 6 nodes
def create_fully_connected_edge_index(num_nodes):
    """
    Creates a fully connected edge index for a graph with num_nodes nodes.
    """
    edges = [(i, j) for i in range(num_nodes) for j in range(num_nodes) if i != j]
    edge_index = torch.tensor(edges, dtype=torch.long).t()  # Transpose to match PyTorch format
    return edge_index


# Example input: 6 models, each outputting probabilities for 6 algorithms
num_models = 6
input_dim = 10  # Each node has 10 probabilities
hidden_dim = 64  # Hidden layer size
output_dim = 10  # Final output for classification

# Simulated data: Probabilities for 6 models (6 features per node)
# node_features = torch.rand((num_models, input_dim))  # Replace with actual model probabilities
edge_index = create_fully_connected_edge_index(num_models)  # Fully connected graph
# labels = torch.tensor([2])  # Example target label for the combined output
# batch = torch.zeros(num_models, dtype=torch.long)  # Single graph, so all nodes in the same batch

# Create graph data
train_data = Data(x=node_features_training_tensor, edge_index=edge_index, y=labels_training_tensor, batch=batch_training_tensor)
val_data = Data(x=node_features_validation_tensor, edge_index=edge_index, y=labels_validation_tensor, batch=batch_validation_tensor)
test_data = Data(x=node_features_testing_tensor, edge_index=edge_index, y=labels_testing_tensor, batch=batch_testing_tensor)
print(train_data.x.shape)

# Initialize and train the GNN
model = GNN(input_dim, hidden_dim, output_dim)
optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
loss_fn = torch.nn.NLLLoss()

# Training loop with validation
best_val_loss = float('inf')
patience = 10
patience_counter = 0

for epoch in range(epochs):
    # Train
    model.train()
    optimizer.zero_grad()
    out = model(train_data.x, train_data.edge_index, train_data.batch)
    loss = loss_fn(out, train_data.y)
    loss.backward()
    optimizer.step()

    # Validate
    model.eval()
    with torch.no_grad():
        val_out = model(val_data.x, val_data.edge_index, val_data.batch)
        val_loss = loss_fn(val_out, val_data.y)

    print(f'Epoch {epoch+1}, Training Loss: {loss.item():.4f}, Validation Loss: {val_loss.item():.4f}')

    # Early stopping
    if val_loss < best_val_loss:
        best_val_loss = val_loss
        patience_counter = 0  # Reset patience
    else:
        patience_counter += 1

    if patience_counter >= patience:
        print("Early stopping triggered!")
        break

# # Switch to evaluation mode
# model.eval()
# with torch.no_grad():
#     predictions = model(test_data.x, test_data.edge_index, test_data.batch)
#     predicted_classes = predictions.argmax(dim=1)
#     print("Predicted classes:", predicted_classes)
#     print(predicted_classes.shape)
#     print("True classes:", test_data.y)
#     print(test_data.y.shape)
#     accuracy = (predicted_classes == test_data.y).float().mean().item()
#     print(f'Test Accuracy: {accuracy * 100:.2f}%')

pickle.dump(model, open("model.pkl", "wb"))
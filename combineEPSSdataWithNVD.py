import pandas as pd
import sys
from datetime import datetime

def write_debug_info(message, data):
    with open("debug_info.txt", "a") as f:
        f.write(message + "\n")
        f.write(str(data.head()) + "\n")

def merge_csv_files(source1, source2):
    try:
        # Read the CSV files into pandas DataFrames
        df1 = pd.read_csv(source1)
        df2 = pd.read_csv(source2)

        col1 = df1.columns[0]
        col2 = df2.columns[0]
        new_col = df2.columns[1]

        # Write debug info to file
        write_debug_info(f"First few rows of {col1} from Source1:", df1[col1])
        write_debug_info(f"First few rows of {col2} from Source2:", df2[col2])

        # Copy df1 data to a new DataFrame
        merged_df = df1.copy()

        # Perform a "VLOOKUP" style operation to populate the new column
        merged_df[new_col] = merged_df[col1].map(df2.set_index(col2)[new_col])

        # Write debug info to file
        write_debug_info("First few rows of merged data:", merged_df)

        # Generate the output filename
        current_date = datetime.now().strftime("%m%d%Y")
        output_filename = f"cvss-epss-data-{current_date}.csv"

        # Write the DataFrame to a new CSV file
        merged_df.to_csv(output_filename, index=False)
        
    except Exception as e:
        with open("debug_info.txt", "a") as f:
            f.write(f"An error occurred: {e}\n")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        source1 = sys.argv[1]
        source2 = sys.argv[2]
    else:
        source1 = input("Please enter the path to the NVD data (Source1) CSV file: ")
        source2 = input("Please enter the path to the EPSS data (Source2) CSV file: ")

    merge_csv_files(source1, source2)

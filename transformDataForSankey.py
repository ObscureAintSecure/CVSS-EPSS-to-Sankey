import pandas as pd
import argparse
from datetime import datetime

# Function to categorize CVSS scores into specified ranges
def categorize_cvss_score(score):
    if pd.isna(score) or score == 'unscored':
        return 'unscored'
    try:
        score = float(score)
    except ValueError:
        return None
		
    if score == 10:
        return '10'
    elif 9 <= score <= 9.9:
        return '9-9.9'
    elif 8 <= score <= 8.9:
        return '8-8.9'
    elif 7 <= score <= 7.9:
        return '7-7.9'
    elif 6 <= score <= 6.9:
        return '6-6.9'
    elif 5 <= score <= 5.9:
        return '5-5.9'
    elif 0 <= score <= 4.9:
        return '0-4.9'
    else:
        return None

# Function to categorize EPSS scores into specified ranges
def categorize_epss_score_percent(score):
    if score >= 0.975:
        return '97.5%'
    elif 0.778 <= score < 0.975:
        return '77.8%'
    elif 0.179 <= score < 0.778:
        return '17.9%'
    elif 0.01 <= score < 0.179:
        return '1%'
    elif 0.0017 <= score < 0.01:
        return '.17%'
    elif 0.00061 <= score < 0.0017:
        return '.061%'
    elif score < 0.00061:
        return '.042%'
    else:
        return None

# Function to categorize CVEs as scored or unscored
def categorize_cve_status(cve):
    return 'scored' if pd.notna(cve) else 'unscored'

def main(file_path):
    # Define a dictionary to map 'Destination' values to colors
    destination_color_map = {
        'National Vulnerability Database': '#F88E8E',
        'CVE Count': '#F88E8E',
        '10': '#FF7A7B',
        '9-9.9': '#FEAB77',
        '8-8.9': '#FDC272',
        '7-7.9': '#FEE588',
        '6-6.9': '#FEFA7F',
        '5-5.9': '#EDFEAE',
        '0-4.9': '#C4F188',
        '97.5%': '#E93F3B',
        '77.8%': '#FFD68C',
        '17.9%': '#D9AC5E',
        '1%': '#FFFF8B',
        '.17%': '#FFFF8B',
        '.061%': '#EDFEB0',
        '.042%': '#C4F188',
		'unscored': '#CCCCCC'
    }
    
    # Read the CSV data into a DataFrame with low_memory set to False
    df = pd.read_csv(file_path, low_memory=False)

    # Add a column to categorize CVEs as scored or unscored
    df['CVE Status'] = df['CVE'].apply(categorize_cve_status)

    # Count the number of scored and unscored CVEs
    cve_status_counts = df['CVE Status'].value_counts().reset_index()
    cve_status_counts = cve_status_counts[cve_status_counts['CVE Status'] == 'unscored']  # Keep only 'unscored' rows
    cve_status_counts.columns = ['CVE Status', 'Weight']
    cve_status_counts['Source'] = 'CVE Count'
    cve_status_counts = cve_status_counts[['Source', 'CVE Status', 'Weight']]
	
    # Update column names to match those in your CSV
    df['CVSS Score Range'] = df['baseScore'].apply(categorize_cvss_score)
    df['EPSS Score Range'] = df['epss'].apply(categorize_epss_score_percent)

    # Count the CVEs for each CVSS Score Range
    cvss_counts = df['CVSS Score Range'].value_counts().reset_index()
    cvss_counts.columns = ['CVSS Score Range', 'Weight']
    cvss_counts['Source'] = 'CVE Count'
    cvss_counts = cvss_counts[['Source', 'CVSS Score Range', 'Weight']]

    # Count the CVEs for each combination of CVSS Score Range and EPSS Score Range
    cvss_epss_counts = df.groupby(['CVSS Score Range', 'EPSS Score Range']).size().reset_index(name='Weight')
    cvss_epss_counts.columns = ['Source', 'Destination', 'Weight']

    # Add a node for "National Vulnerability Database" with the total CVE count
    total_cve_count = len(df)
    nvd_node = pd.DataFrame({
        'Source': ['National Vulnerability Database'],
        'Weight': [total_cve_count],
        'Destination': ['CVE Count']
    })

    # Combine all DataFrames
    sankey_data = pd.concat([nvd_node, cve_status_counts.rename(columns={'CVE Status': 'Destination'}), cvss_counts.rename(columns={'CVSS Score Range': 'Destination'}), cvss_epss_counts], ignore_index=True)

    # Add square brackets around each item in the 'Weight' column
    sankey_data['Weight'] = sankey_data['Weight'].apply(lambda x: f'[{x}]')

    # Define a custom sort order for the "CVE Count" destinations
    custom_order = ['10', '9-9.9', '8-8.9', '7-7.9', '6-6.9', '5-5.9', '0-4.9', 'unscored']

    # Sort the DataFrame according to this custom order, but only where Source is "CVE Count"
    cve_count_rows = sankey_data[sankey_data['Source'] == 'CVE Count'].copy()
    cve_count_rows['Destination'] = pd.Categorical(cve_count_rows['Destination'], categories=custom_order, ordered=True)
    cve_count_rows = cve_count_rows.sort_values('Destination')

    # Replace the original "CVE Count" rows with the sorted rows
    sankey_data = pd.concat([sankey_data[sankey_data['Source'] != 'CVE Count'], cve_count_rows])

    # Define the custom sort order for the "Source" column and the "Destination" column
    source_order = ['National Vulnerability Database', 'CVE Count', '10', '9-9.9', '8-8.9', '7-7.9', '6-6.9', '5-5.9', '0-4.9', 'unscored']
    destination_order = ['CVE Count', '10', '9-9.9', '8-8.9', '7-7.9', '6-6.9', '5-5.9', '0-4.9', 'unscored', '97.5%', '77.8%', '17.9%', '1%', '.17%', '.061%', '.042%']
    
    # Convert the "Source" and "Destination" columns to categorical types with the custom sort order
    sankey_data['Source'] = pd.Categorical(sankey_data['Source'], categories=source_order, ordered=True)
    sankey_data['Destination'] = pd.Categorical(sankey_data['Destination'], categories=destination_order, ordered=True)

    # Sort the DataFrame first by "Source" and then by "Destination"
    sankey_data.sort_values(['Source', 'Destination'], ascending=[True, True], inplace=True)
	
    # Add a new 'Color' column based on the 'Destination' column
    sankey_data['Color'] = sankey_data['Destination'].map(destination_color_map)

    # Generate the current date in MMDDYYYY format
    current_date = datetime.now().strftime('%m%d%Y')
	
    # Save the structured data to a new CSV file with the current date appended to the filename
    output_file = f'sankey_data-{current_date}.csv'
    sankey_data.to_csv(output_file, index=False, sep=' ')

    # Add the static data starting three rows below the original data
    static_data = pd.DataFrame({
        'column1': [
            '',
            '',
            '// Node color:',
            ':National Vulnerability Database #ED0401',
            ':CVE Count #F88E8E',
            ':10 #FF0D00',
            ':9-9.9 #FFA500',
            ':8-8.9 #FDA935',
            ':7-7.9 #FDDB56',
            ':6-6.9 #FDF54A',
            ':5-5.9 #E1FD82',
            ':0-4.9 #ACEA57',
            ':97.5% #FF0D00',
            ':77.8% #FFA500',
            ':17.9% #FDA935',
            ':1% #FDDB56',
            ':.17% #FDF54A',
            ':.061% #E1FD82',
            ':.042% #ACEA57',
			':unscored #A4A4A4'
        ]
    })

    # Append the static data to the existing CSV file
    static_data.to_csv(output_file, mode='a', index=False, header=False)

    with open(output_file, 'r+') as f:
	    content = f.read()
	    f.seek(0)
	    f.write(content.replace('"', ''))
	    f.truncate()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Transform CSV data for Sankey diagram.')
    parser.add_argument('--file', help='Path to the CSV file to transform')
    args = parser.parse_args()

    if args.file:
        file_path = args.file
    else:
        file_path = input('Please enter the path to the CSV file to transform: ')

    
    main(file_path)

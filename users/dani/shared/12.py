import pandas as pd

# Load the dataset into pandas DataFrame
# Replace 'your_dataset.csv' with the actual path to your dataset
df = pd.read_csv(r"D:\code\SY\Python\hotel_bookings.csv")

# Perform initial data exploration
# Display the first 5 rows of the dataset
print("First 5 rows of the dataset:")
print(df.head())

# Check for missing values
print("\nCheck for missing values:")
print(df.isnull().sum())

# Handle missing values (consider other strategies like imputation)
df = df.dropna()

# Remove duplicate entries
df = df.drop_duplicates()

# Display the first 5 rows of the dataset for country 'PRT'
print("\nFirst 5 rows of the dataset for country 'PRT':")
print(df[df['Country'] == 'PRT'].head())

# Data Analysis
# Display entries of hotels where booking has been cancelled
print("\nEntries of hotels where booking has been cancelled:")
print(df[df['BookingStatus'] == 'Cancelled'])

# Display entries with stays of 2 days and more
print("\nEntries with stays of 2 days and more:")
print(df[df['Stays'] >= 2])

# Display entries of the country 'PRT'
print("\nEntries of the country 'PRT':")
print(df[df['Country'] == 'PRT'])

# Identify the month with the highest and lowest bookings
df['BookingMonth'] = pd.to_datetime(df['BookingDate']).dt.month
monthly_bookings = df.groupby('BookingMonth').size()
highest_month = monthly_bookings.idxmax()
lowest_month = monthly_bookings.idxmin()
print("\nMonth with the highest bookings:", highest_month)
print("Month with the lowest bookings:", lowest_month)

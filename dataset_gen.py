import pandas as pd
import numpy as np

# Generate synthetic data
np.random.seed(42)
n_samples = 1000

data = {
    'cpu_usage': np.random.normal(50, 10, n_samples),
    'memory_usage': np.random.normal(50, 10, n_samples),
    'network_traffic': np.random.normal(1000, 200, n_samples),
    'usb_connected': np.random.choice([0, 1], n_samples, p=[0.9, 0.1])
}

df = pd.DataFrame(data)

# Add some anomalies
df.loc[950:999, 'cpu_usage'] = np.random.normal(90, 5, 50)
df.loc[950:999, 'memory_usage'] = np.random.normal(90, 5, 50)
df.loc[950:999, 'network_traffic'] = np.random.normal(2000, 500, 50)
df.loc[950:999, 'usb_connected'] = 1

# Save the dataset
df.to_csv('insider_threat_dataset.csv', index=False)
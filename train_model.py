from sklearn.ensemble import IsolationForest
import pandas as pd

# Load the dataset
df = pd.read_csv('insider_threat_dataset.csv')

# Train the model
model = IsolationForest(contamination=0.05, random_state=42)
model.fit(df)

# Save the model
import joblib
joblib.dump(model, 'anomaly_detection_model.pkl')
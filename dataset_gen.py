# generate_anomaly_dataset.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import random
import json
import os

def generate_synthetic_data(num_normal=1000, num_anomalous=50):
    """Generate synthetic system monitoring data with anomalies"""
    data = []
    
    # Generate normal data
    for _ in range(num_normal):
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 10080))  # Up to 1 week ago
        cpu = random.normalvariate(30, 10)
        memory = random.normalvariate(40, 15)
        network = random.normalvariate(500000, 200000)  # bytes
        usb_connected = 0
        
        data.append({
            "timestamp": timestamp.isoformat(),
            "cpu_percent": max(0, min(100, cpu)),
            "memory_percent": max(0, min(100, memory)),
            "network_bytes": max(0, network),
            "usb_connected": usb_connected,
            "is_anomaly": 0
        })
    
    # Generate anomalous data
    for _ in range(num_anomalous):
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 10080))
        
        # Different types of anomalies
        anomaly_type = random.choice(["cpu", "memory", "network", "usb", "combined"])
        
        if anomaly_type == "cpu":
            cpu = random.normalvariate(85, 5)
            memory = random.normalvariate(40, 15)
            network = random.normalvariate(500000, 200000)
            usb_connected = 0
        elif anomaly_type == "memory":
            cpu = random.normalvariate(30, 10)
            memory = random.normalvariate(85, 5)
            network = random.normalvariate(500000, 200000)
            usb_connected = 0
        elif anomaly_type == "network":
            cpu = random.normalvariate(30, 10)
            memory = random.normalvariate(40, 15)
            network = random.normalvariate(2000000, 500000)
            usb_connected = 0
        elif anomaly_type == "usb":
            cpu = random.normalvariate(30, 10)
            memory = random.normalvariate(40, 15)
            network = random.normalvariate(500000, 200000)
            usb_connected = 1
        else:  # combined
            cpu = random.normalvariate(80, 10)
            memory = random.normalvariate(75, 10)
            network = random.normalvariate(1500000, 500000)
            usb_connected = random.choice([0, 1])
        
        data.append({
            "timestamp": timestamp.isoformat(),
            "cpu_percent": max(0, min(100, cpu)),
            "memory_percent": max(0, min(100, memory)),
            "network_bytes": max(0, network),
            "usb_connected": usb_connected,
            "is_anomaly": 1
        })
    
    return pd.DataFrame(data)

def save_dataset(df, filename="anomaly_dataset.csv"):
    """Save the generated dataset"""
    df.to_csv(filename, index=False)
    print(f"Dataset saved to {filename}")

def train_anomaly_detection_model(df):
    """Train an Isolation Forest model on the generated data"""
    # Prepare features
    features = df[["cpu_percent", "memory_percent", "network_bytes", "usb_connected"]]
    
    # Train model
    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination=0.05,  # expected proportion of anomalies
        max_features=1.0,
        random_state=42
    )
    
    model.fit(features)
    
    # Save the model
    import joblib
    joblib.dump(model, "anomaly_detection_model.pkl")
    print("Model trained and saved to anomaly_detection_model.pkl")
    
    # Add predictions to dataframe for analysis
    df['prediction'] = model.predict(features)
    df['anomaly_score'] = model.decision_function(features)
    
    return df, model

if __name__ == "__main__":
    # Generate and save synthetic data
    df = generate_synthetic_data()
    save_dataset(df)
    
    # Train and save model
    df_with_predictions, model = train_anomaly_detection_model(df)
    
    # Analyze performance
    print("\nAnomaly Detection Performance:")
    print(f"Total anomalies detected: {(df_with_predictions['prediction'] == -1).sum()}")
    print(f"Actual anomalies in data: {df_with_predictions['is_anomaly'].sum()}")
    
    true_positives = ((df_with_predictions['prediction'] == -1) & (df_with_predictions['is_anomaly'] == 1)).sum()
    false_positives = ((df_with_predictions['prediction'] == -1) & (df_with_predictions['is_anomaly'] == 0)).sum()
    
    print(f"True Positives: {true_positives}")
    print(f"False Positives: {false_positives}")
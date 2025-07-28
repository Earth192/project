import pandas as pd
from ids.DetectionEngine import DetectionEngine
from logs_gen_engine import extract_features

def test_log_batch(csv_path='firewall_logs.csv'):
    df = pd.read_csv(csv_path)
    engine = DetectionEngine()
    threat_summary = {}

    for _, row in df.iterrows():
        features = extract_features(row)
        threats = engine.detect_threats(features)
        for threat in threats:
            threat_type = threat['type']
            threat_summary[threat_type] = threat_summary.get(threat_type, 0) + 1

    print("\n🧪 Batch Log Threat Summary")
    for threat_type, count in threat_summary.items():
        print(f"  🚨 {threat_type}: {count} detections")

    print(f"\n✅ Processed {len(df)} log entries")

if __name__ == "__main__":
    test_log_batch()

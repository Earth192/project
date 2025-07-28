# analyze_firewall_logs.py

import pandas as pd
from ids.DetectionEngine import DetectionEngine  # Adjust as needed

def process_logs(csv_path='firewall_logs.csv', output_path='detected_threats.csv'):
    df = pd.read_csv(csv_path)
    engine = DetectionEngine()
    output = []

    def extract_features(row):
        return {
            'src_ip': row.get('src_ip'),
            'dst_ip': row.get('dst_ip'),
            'src_port': row.get('src_port'),
            'dst_port': row.get('dst_port'),
            'protocol': row.get('protocol'),
            'packet_size': row.get('packet_size'),
            'flags': row.get('flags'),
            'timestamp': row.get('timestamp')
        }

    for index, row in df.iterrows():
        features = extract_features(row)
        threats = engine.detect_threats(features)
        for threat in threats:
            output.append({
                'row': index,
                'timestamp': features['timestamp'],
                'src_ip': features['src_ip'],
                'dst_ip': features['dst_ip'],
                'threat_type': threat['type'],
                'detail': threat.get('rule') or threat.get('score'),
                'confidence': threat.get('confidence')
            })

    pd.DataFrame(output).to_csv(output_path, index=False)
    print(f"✅ Saved {len(output)} threats to {output_path}")

import pandas as pd
import time
import logging
from ids.DetectionEngine import DetectionEngine
from logs_gen_engine import generate_logs

def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("ids_system.log"),
            logging.StreamHandler()
        ]
    )
    detection_log = logging.FileHandler("ids_detections.log")
    detection_log.setLevel(logging.WARNING)
    detection_log.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logging.getLogger('DetectionEngine').addHandler(detection_log)

def main():
    configure_logging()
    print("Initializing Detection Engine...")
    engine = DetectionEngine()

    print("\n=== Model Load Attempt ===")
    if not engine.load_models():
        print("⚠️ No pretrained models found. Starting training from CSV...")
        engine.train_from_csv("/Users/jenish/Documents/IDS/firewall_logs.csv")
        engine.save_models()
    else:
        print("✅ Loaded pretrained models.")

    # Display training status
    status = engine.get_training_status()
    print("\nTraining Status:")
    print(f"- Unsupervised Model: {'Trained' if status['unsupervised']['is_trained'] else 'Not Trained'}")
    print(f"- Supervised Model: {'Trained' if status['supervised']['is_trained'] else 'Not Trained'}")
    print(f"- Normal Traffic Ranges: {status['normal_ranges']}")

    # 5-feature test cases
    print("\n=== Detection Demonstration ===")
    test_cases = [
    {
        'name': "Normal Firewall Log Sample",
        'features': {
            'src_ip': 100,
            'dst_ip': 101,
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 6,
            'packet_size': 512,
            'packet_rate': 30,
            'byte_rate': 15000,
            'tcp_flags': 0
        }
    },
    {
        'name': "Suspicious High Packet Rate",
        'features': {
            'src_ip': 110,
            'dst_ip': 111,
            'src_port': 33333,
            'dst_port': 443,
            'protocol': 6,
            'packet_size': 128,
            'packet_rate': 120,  # triggers SYN flood rule
            'byte_rate': 8000,
            'tcp_flags': 2       # SYN flag
        }
    },
    {
        'name': "Anomalous Oversized Packet",
        'features': {
            'src_ip': 120,
            'dst_ip': 121,
            'src_port': 55555,
            'dst_port': 22,
            'protocol': 6,
            'packet_size': 2000,  # triggers oversized packet rule
            'packet_rate': 10,
            'byte_rate': 20000,
            'tcp_flags': 0
        }
    }
]


    for case in test_cases:
        print(f"\nTesting: {case['name']}")
        print(f"Features: {case['features']}")
        start_time = time.time()
        threats = engine.detect_threats(case['features'])
        detection_time = (time.time() - start_time) * 1000
        if not threats:
            print("✅ No threats detected")
        else:
            for threat in threats:
                print(f"🚨 THREAT DETECTED:")
                print(f"  Type: {threat['type']}")
                print(f"  Description: {threat['description']}")
                print(f"  Severity: {threat['severity'].upper()}")
                print(f"  Confidence: {threat['confidence']:.2f}")
                if 'mitigation' in threat:
                    print(f"  Mitigation: {threat['mitigation']}")
        print(f"Detection time: {detection_time:.2f}ms")

    print("\n=== System Ready for Real-Time Monitoring ===")
    print("Press Ctrl+C to exit...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down detection system...")

if __name__ == "__main__":
    main()

#regenerate logs if needed
generate_logs(count=100)

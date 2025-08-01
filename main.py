import time
import logging
from ids.DetectionEngine import DetectionEngine
from logs_gen_engine import generate_ip


def configure_logging():
    # Main log file
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("ids_system.log"),
            logging.StreamHandler()
        ]
    )
    
    # Detection-specific log
    detection_log = logging.FileHandler("ids_detections.log")
    detection_log.setLevel(logging.WARNING)
    detection_log.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logging.getLogger('DetectionEngine').addHandler(detection_log)

def main():

    configure_logging()

    # Initialize the detection engine
    print("Initializing Detection Engine...")
    engine = DetectionEngine()
    
    # Training phase
    print("\n=== Training Phase ===")
    train_success = engine.train_model(num_samples=2000)
    
    if not train_success:
        print("Training failed. Exiting...")
        return
     
    # Display training status
    status = engine.get_training_status()
    print("\nTraining Status:")
    print(f"- Unsupervised Model: {'Trained' if status['unsupervised']['is_trained'] else 'Not Trained'}")
    print(f"- Supervised Model: {'Trained' if status['supervised']['is_trained'] else 'Not Trained'}")
    print(f"- Normal Traffic Ranges:")
    for feature, stats in status['normal_ranges'].items():
        print(f"  {feature}: {stats['min']:.2f}-{stats['max']:.2f} (mean: {stats['mean']:.2f})")
    
    # Demonstration phase
    print("\n=== Detection Demonstration ===")
    test_cases = [
        {
            'name': "Normal Traffic",
            'features': {
                'packet_size': 120,
                'packet_rate': 15,
                'byte_rate': 1800,
                'tcp_flags': 0
            }
        },
        {
            'name': "SYN Flood Attack",
            'features': {
                'packet_size': 60,
                'packet_rate': 150,
                'byte_rate': 9000,
                'tcp_flags': 2
            }
        },
        {
            'name': "Port Scan",
            'features': {
                'packet_size': 80,
                'packet_rate': 75,
                'byte_rate': 6000,
                'tcp_flags': 0
            }
        },
        {
            'name': "Anomalous Traffic",
            'features': {
                'packet_size': 2000,
                'packet_rate': 0.5,
                'byte_rate': 30000,
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
    
    # Continuous monitoring simulation
    try:
        while True:
            #get packets from your PacketCapture system
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down detection system...")

if __name__ == "__main__":
    main()



# Generating logs after IDS run
generate_logs(log_count=100)


import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import logging
import os
import joblib
from collections import defaultdict
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

class DetectionEngine:
    def __init__(self, log_file="ids_detection.log"):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        self.supervised_classifier = RandomForestClassifier(random_state=42, n_estimators=100, class_weight='balanced')

        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.training_labels = []
        self.normal_traffic_stats = defaultdict(list)
        self.is_trained_unsupervised = False
        self.is_trained_supervised = False
        self.model_dir = "IDS/models"
        os.makedirs(self.model_dir, exist_ok=True)

        self.logger = logging.getLogger('DetectionEngine')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.info("Detection Engine initialized")

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda f: (f['tcp_flags'] == 2 and f['packet_rate'] > 100),
                'description': "SYN flood attack detected",
                'severity': "critical",
                'mitigation': "Enable SYN cookies and rate limiting"
            },
            'port_scan': {
                'condition': lambda f: (f['packet_size'] < 100 and f['packet_rate'] > 50),
                'description': "Port scan activity detected",
                'severity': "high",
                'mitigation': "Implement port knocking or firewall rules"
            },
            'oversized_packet': {
                'condition': lambda f: f['packet_size'] > 1500,
                'description': "Oversized packet detected",
                'severity': "medium",
                'mitigation': "Verify network MTU settings"
            }
        }

    def preprocess_csv(self, csv_path):
        df = pd.read_csv(csv_path)
        for col in ['src_ip', 'dst_ip', 'protocol']:
            df[col] = LabelEncoder().fit_transform(df[col])
        df['label'] = df['action'].apply(lambda x: 1 if x == 'BLOCK' else 0)
        return df

    def train_from_csv(self, csv_path):
        df = self.preprocess_csv(csv_path)
        X = df[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']]
        y = df['label']
        self.anomaly_detector.fit(X)
        self.is_trained_unsupervised = True
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        self.supervised_classifier.fit(X_train, y_train)
        self.is_trained_supervised = True
        y_pred = self.supervised_classifier.predict(X_test)
        self.logger.info("\n" + classification_report(y_test, y_pred))

    def save_models(self):
        joblib.dump(self.anomaly_detector, os.path.join(self.model_dir, "isolation_model.pkl"))
        joblib.dump(self.supervised_classifier, os.path.join(self.model_dir, "rf_model.pkl"))

    def load_models(self):
        iso_path = os.path.join(self.model_dir, "isolation_model.pkl")
        rf_path = os.path.join(self.model_dir, "rf_model.pkl")
        if os.path.exists(iso_path):
            self.anomaly_detector = joblib.load(iso_path)
            self.is_trained_unsupervised = True
        if os.path.exists(rf_path):
            self.supervised_classifier = joblib.load(rf_path)
            self.is_trained_supervised = True

    def detect_threats(self, features):
        threats = []
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'confidence': 1.0,
                    'mitigation': rule.get('mitigation', 'Investigate manually'),
                    'features': self._format_features(features)
                })

        try:
            feature_vector = pd.DataFrame([{
    'src_ip': features['src_ip'],
    'dst_ip': features['dst_ip'],
    'src_port': features['src_port'],
    'dst_port': features['dst_port'],
    'protocol': features['protocol']
}])
        except KeyError as e:
            self.logger.warning(f"Missing feature: {str(e)}")
            return threats

        if self.is_trained_unsupervised:
            try:
                score = self.anomaly_detector.score_samples(feature_vector)[0]
                if score < -0.5:
                    conf = min(1.0, abs(score))
                    threats.append({
                        'type': 'anomaly',
                        'score': float(score),
                        'confidence': conf,
                        'description': f"Anomalous traffic (score: {score:.2f})",
                        'severity': "critical" if score < -0.8 else "high",
                        'mitigation': "Investigate for zero-day attacks",
                        'features': self._format_features(features)
                    })
            except Exception as e:
                self.logger.error(f"Anomaly detection failed: {str(e)}")

        if self.is_trained_supervised:
            try:
                proba = self.supervised_classifier.predict_proba(feature_vector)[0]
                if proba[1] > 0.6:
                    threats.append({
                        'type': 'supervised',
                        'confidence': float(proba[1]),
                        'description': "Classifier detected attack pattern",
                        'severity': "critical" if proba[1] > 0.9 else "high",
                        'mitigation': "Review similar historical attacks",
                        'features': self._format_features(features)
                    })
            except Exception as e:
                self.logger.error(f"Classification failed: {str(e)}")

        return self._prioritize_threats(threats)

    def _format_features(self, features):
        return {
            'packet_size': features.get('packet_size', 0),
            'packet_rate': features.get('packet_rate', 0),
            'byte_rate': features.get('byte_rate', 0),
            'tcp_flags': features.get('tcp_flags', 0),
            'protocol': features.get('protocol', 'unknown')
        }

    def _prioritize_threats(self, threats):
        unique_threats = []
        seen = set()
        for t in threats:
            key = (t['type'], t.get('rule', ''), t['description'])
            if key not in seen:
                seen.add(key)
                unique_threats.append(t)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return sorted(unique_threats, key=lambda x: severity_order[x['severity']])

    def get_training_status(self):
        status = {
            'unsupervised': {
                'is_trained': self.is_trained_unsupervised,
                'samples': len(self.training_data) if self.training_data else 0
            },
            'supervised': {
                'is_trained': self.is_trained_supervised,
                'samples': len(self.training_labels) if self.training_labels else 0,
                'class_balance': np.bincount(self.training_labels).tolist() if self.training_labels else None
            },
            'normal_ranges': {
                'packet_size': self._get_stats_range('packet_size'),
                'packet_rate': self._get_stats_range('packet_rate'),
                'byte_rate': self._get_stats_range('byte_rate')
            }
        }
        return status

    def _get_stats_range(self, feature):
        if feature in self.normal_traffic_stats and self.normal_traffic_stats[feature]:
            vals = self.normal_traffic_stats[feature]
            return {
                'min': float(np.min(vals)),
                'max': float(np.max(vals)),
                'mean': float(np.mean(vals)),
                'std': float(np.std(vals))
            }
        return None

    def visualize_training_data(self, X=None, y=None):
        if X is None or y is None:
            if not self.training_data:
                self.logger.warning("No training data to visualize")
                return
            X = np.array(self.training_data)
            y = np.array(self.training_labels) if self.training_labels else np.zeros(len(X))

        plt.figure(figsize=(18, 6))
        plt.subplot(131)
        for i, name in enumerate(['Packet Size', 'Packet Rate', 'Byte Rate']):
            plt.hist(X[:,i][y==0], bins=30, alpha=0.5, label=f'Normal {name}' if i==0 else "")
            plt.hist(X[:,i][y==1], bins=30, alpha=0.5, label=f'Attack {name}' if i==0 else "")
        plt.yscale('log')
        plt.legend()
        plt.title('Feature Distributions')

        plt.subplot(132)
        plt.scatter(X[:,0][y==0], X[:,1][y==0], c='blue', alpha=0.3, label='Normal')
        plt.scatter(X[:,0][y==1], X[:,1][y==1], c='red', alpha=0.3, label='Attack')
        plt.xlabel('Packet Size')
        plt.ylabel('Packet Rate')
        plt.title('Decision Space')
        plt.legend()

        ax = plt.subplot(133, projection='3d')
        ax.scatter(X[:,0][y==0], X[:,1][y==0], X[:,2][y==0], c='blue', alpha=0.3, label='Normal')
        ax.scatter(X[:,0][y==1], X[:,1][y==1], X[:,2][y==1], c='red', alpha=0.3, label='Attack')
        ax.set_xlabel('Packet Size')
        ax.set_ylabel('Packet Rate')
        ax.set_zlabel('Byte Rate')
        plt.title('3D Feature Space')
        plt.tight_layout()
        plt.show()

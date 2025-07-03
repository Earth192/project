from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
import logging

class DetectionEngine:
    def __init__(self, log_file="ids_detection.log"):
        # Initialize detectors
        self.anomaly_detector = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        self.supervised_classifier = RandomForestClassifier(
            random_state=42,
            n_estimators=100,
            class_weight='balanced'
        )
        
        # Rule-based system
        self.signature_rules = self.load_signature_rules()
        
        # Training data storage
        self.training_data = []
        self.training_labels = []
        self.normal_traffic_stats = defaultdict(list)


        # Training status flags
        self.is_trained_unsupervised = False
        self.is_trained_supervised = False
        
    

        # Configure logging
        
        self.logger = logging.getLogger('DetectionEngine')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

         # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # File handler  q12
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        self.logger.info("Detection Engine initialized")




    def load_signature_rules(self):
        """Enhanced signature rules with mitigation suggestions"""
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

    def generate_training_data(self, num_normal=2000, num_attacks=500):
        """Enhanced synthetic data generation with more attack types"""
        np.random.seed(42)
        
        # Normal traffic with more realistic distributions
        normal = self._generate_normal_traffic(num_normal)
        
        # Enhanced attack patterns
        attacks = self._generate_attack_traffic(num_attacks)
        
        X = np.vstack((normal, attacks))
        y = np.array([0]*num_normal + [1]*num_attacks)
        
        self.logger.info(f"Generated {len(X)} samples ({num_normal} normal, {num_attacks} attacks)")
        return X, y

    def _generate_normal_traffic(self, n):
        """More sophisticated normal traffic simulation"""
        # Base traffic
        packet_size = np.clip(
            np.random.weibull(1.5, n) * 100, 60, 1500
        )
        packet_rate = np.clip(
            np.random.poisson(15, n), 1, 50
        )
        byte_rate = packet_size * packet_rate * np.random.uniform(0.8, 1.2, n)
        
        # Store stats
        stats = {
            'packet_size': packet_size,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate
        }
        
        for k, v in stats.items():
            self.normal_traffic_stats[k].extend(v)
            
        return np.column_stack((packet_size, packet_rate, byte_rate))

    def _generate_attack_traffic(self, n):
        """Enhanced attack traffic with more variants"""
        attacks = []
        
        # SYN Flood (20%)
        syn_flood = np.column_stack((
            np.full(int(n*0.2), 60),
            np.random.uniform(100, 300, int(n*0.2)),
            np.random.uniform(8000, 15000, int(n*0.2))
        ))
        
        # Port Scan (20%)
        port_scan = np.column_stack((
            np.random.uniform(40, 100, int(n*0.2)),
            np.random.uniform(50, 200, int(n*0.2)),
            np.random.uniform(2000, 8000, int(n*0.2))
        ))
        
        # Oversized Packets (15%)
        oversized = np.column_stack((
            np.random.uniform(1500, 9000, int(n*0.15)),
            np.random.uniform(1, 50, int(n*0.15)),
            np.random.uniform(10000, 50000, int(n*0.15))
        ))
        
        # Slow Rate Attacks (15%)
        slow_rate = np.column_stack((
            np.random.uniform(60, 1500, int(n*0.15)),
            np.random.uniform(0.1, 1, int(n*0.15)),
            np.random.uniform(10, 1000, int(n*0.15))
        ))
        
        # Protocol Anomalies (30%)
        anomalies = np.column_stack((
            np.random.uniform(10, 9000, n - int(n*0.7)),
            np.random.uniform(0.1, 300, n - int(n*0.7)),
            np.random.uniform(10, 60000, n - int(n*0.7))
        ))
        
        return np.vstack((syn_flood, port_scan, oversized, slow_rate, anomalies))

    def train_model(self, num_samples=2000):
        """Complete training pipeline with validation"""
        try:
            X, y = self.generate_training_data(num_normal=num_samples)
            
            # Train unsupervised model
            self.train_anomaly_detector(X[y==0])
            
            # Train supervised model
            self.train_supervised_classifier(X, y)
            
            # Evaluate performance
            self.evaluate_models(X, y)
            
            return True
        except Exception as e:
            self.logger.error(f"Training failed: {str(e)}")
            return False

    def train_anomaly_detector(self, normal_traffic_data):
        """Enhanced anomaly detector training"""
        X = np.array(normal_traffic_data)
        if X.shape[1] != 3:
            raise ValueError("Requires exactly 3 features")
            
        self.anomaly_detector.fit(X)
        self.is_trained_unsupervised = True
        self.training_data = X.tolist()
        self.logger.info("Anomaly detector trained successfully")

    def train_supervised_classifier(self, X, y):
        """Enhanced supervised classifier training"""
        self.supervised_classifier.fit(X, y)
        self.is_trained_supervised = True
        self.training_labels = y.tolist()
        self.logger.info("Supervised classifier trained successfully")

    def evaluate_models(self, X, y):
        """Model evaluation with detailed metrics"""
        if self.is_trained_supervised:
            y_pred = self.supervised_classifier.predict(X)
            self.logger.info("\nSupervised Model Evaluation:\n" + 
                classification_report(y, y_pred, target_names=['Normal', 'Attack']))
        
        if self.is_trained_unsupervised:
            scores = self.anomaly_detector.score_samples(X)
            threshold = np.percentile(scores[y==0], 5)  # 5th percentile of normal scores
            y_pred = (scores < threshold).astype(int)
            self.logger.info("\nAnomaly Detection Evaluation:\n" + 
                classification_report(y, y_pred, target_names=['Normal', 'Anomaly']))

    def detect_threats(self, features):
        """Enhanced threat detection with confidence scoring"""
        threats = []
        
        # Signature-based detection
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

        # Prepare feature vector
        try:
            feature_vector = np.array([[
                features['packet_size'],
                features['packet_rate'], 
                features['byte_rate']
            ]])
        except KeyError as e:
            self.logger.warning(f"Missing feature: {str(e)}")
            return threats

        # Anomaly detection
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

        # Supervised classification
        if self.is_trained_supervised:
            try:
                proba = self.supervised_classifier.predict_proba(feature_vector)[0]
                if proba[1] > 0.6:  # Attack class probability threshold
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

        # Deduplicate and prioritize threats
        return self._prioritize_threats(threats)

    def _format_features(self, features):
        """Standardize feature formatting"""
        return {
            'packet_size': features.get('packet_size', 0),
            'packet_rate': features.get('packet_rate', 0),
            'byte_rate': features.get('byte_rate', 0),
            'tcp_flags': features.get('tcp_flags', 0),
            'protocol': features.get('protocol', 'unknown')
        }

    def _prioritize_threats(self, threats):
        """Deduplicate and sort threats by severity"""
        # Remove duplicates
        unique_threats = []
        seen = set()
        for t in threats:
            key = (t['type'], t.get('rule', ''), t['description'])
            if key not in seen:
                seen.add(key)
                unique_threats.append(t)
        
        # Sort by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return sorted(unique_threats, key=lambda x: severity_order[x['severity']])

    def visualize_training_data(self, X=None, y=None):
        """Enhanced visualization with decision boundaries"""
        if X is None or y is None:
            if not self.training_data:
                self.logger.warning("No training data to visualize")
                return
            X = np.array(self.training_data)
            y = np.array(self.training_labels) if self.training_labels else np.zeros(len(X))
        
        plt.figure(figsize=(18, 6))
        
        # Feature distributions
        plt.subplot(131)
        for i, name in enumerate(['Packet Size', 'Packet Rate', 'Byte Rate']):
            plt.hist(X[:,i][y==0], bins=30, alpha=0.5, label=f'Normal {name}' if i==0 else "")
            plt.hist(X[:,i][y==1], bins=30, alpha=0.5, label=f'Attack {name}' if i==0 else "")
        plt.yscale('log')
        plt.legend()
        plt.title('Feature Distributions')
        
        # Packet Size vs Rate
        plt.subplot(132)
        plt.scatter(X[:,0][y==0], X[:,1][y==0], c='blue', alpha=0.3, label='Normal')
        plt.scatter(X[:,0][y==1], X[:,1][y==1], c='red', alpha=0.3, label='Attack')
        
        if self.is_trained_supervised:
            # Create decision boundary
            xx, yy = np.meshgrid(
                np.linspace(0, 2000, 100),
                np.linspace(0, 300, 100))
            Z = self.supervised_classifier.predict(np.c_[xx.ravel(), yy.ravel(), np.zeros_like(xx.ravel())])
            Z = Z.reshape(xx.shape)
            plt.contourf(xx, yy, Z, alpha=0.2, levels=[0, 0.5, 1], colors=['blue', 'red'])
        
        plt.xlabel('Packet Size')
        plt.ylabel('Packet Rate')
        plt.title('Decision Space')
        plt.legend()
        
        # 3D visualization
        ax = plt.subplot(133, projection='3d')
        ax.scatter(X[:,0][y==0], X[:,1][y==0], X[:,2][y==0], c='blue', alpha=0.3, label='Normal')
        ax.scatter(X[:,0][y==1], X[:,1][y==1], X[:,2][y==1], c='red', alpha=0.3, label='Attack')
        ax.set_xlabel('Packet Size')
        ax.set_ylabel('Packet Rate')
        ax.set_zlabel('Byte Rate')
        plt.title('3D Feature Space')
        
        plt.tight_layout()
        plt.show()

    def get_training_status(self):
        """Detailed training status report"""
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
        """Helper for stats range calculation"""
        if feature in self.normal_traffic_stats and self.normal_traffic_stats[feature]:
            vals = self.normal_traffic_stats[feature]
            return {
                'min': float(np.min(vals)),
                'max': float(np.max(vals)),
                'mean': float(np.mean(vals)),
                'std': float(np.std(vals))
            }
        return None
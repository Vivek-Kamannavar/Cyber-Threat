"""
Unsupervised Isolation Forest Model for Volumetric Flow Anomaly Detection
Uses Scikit-Learn IsolationForest to detect statistical outliers in multi-dimensional flow metrics.
Supports model serialization and persistence via joblib for zero cold-start latency.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any, Tuple, Optional
from backend.config import Config


class FlowAnomalyDetector:
    """Isolation Forest anomaly detector trained on flow metrics with persistent disk caching."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42, model_path: Optional[str] = None):
        self.contamination = contamination
        self.random_state = random_state
        self.model_path = model_path or Config.MODEL_PATH
        self.model: Optional[IsolationForest] = None
        self.is_fitted = False

        if self.model_path and os.path.exists(self.model_path):
            try:
                self.load_model(self.model_path)
            except Exception as e:
                print(f"Warning: Failed to load cached model from {self.model_path} ({e}). Recalibrating...")
                self._initialize_and_fit()
        else:
            self._initialize_and_fit()

    def _initialize_and_fit(self):
        """Initializes a new IsolationForest, fits baseline synthetic samples, and saves to disk."""
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self._fit_initial_baseline()
        if self.model_path:
            try:
                self.save_model(self.model_path)
            except Exception as e:
                print(f"Warning: Could not save model to {self.model_path}: {e}")

    def save_model(self, filepath: str):
        """Serializes and saves the fitted model to disk via joblib."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        joblib.dump({"model": self.model, "is_fitted": self.is_fitted}, filepath)

    def load_model(self, filepath: str):
        """Loads a pre-fitted model from disk via joblib."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found at {filepath}")
        loaded = joblib.load(filepath)
        if isinstance(loaded, dict) and "model" in loaded:
            self.model = loaded["model"]
            self.is_fitted = loaded.get("is_fitted", True)
        else:
            self.model = loaded
            self.is_fitted = True

    def _extract_feature_vector(self, flow: Dict[str, Any]) -> List[float]:
        """
        Extracts numeric feature vector:
        [bytes_sent, bytes_received, packet_count, src_port, dst_port]
        """
        fid = flow.get('flow_identifier', {})
        bytes_sent = float(flow.get('bytes_sent', 0))
        bytes_recv = float(flow.get('bytes_received', 0))
        pkts = float(flow.get('packet_count', 1))
        src_port = float(fid.get('src_port', 0))
        dst_port = float(fid.get('dst_port', 0))

        return [bytes_sent, bytes_recv, pkts, src_port, dst_port]

    def _fit_initial_baseline(self):
        """Fits the model with synthetic baseline benign flow samples."""
        np.random.seed(self.random_state)
        # Generate 200 synthetic baseline flow vectors (normal traffic)
        baseline_bytes_sent = np.random.normal(500, 200, 200)
        baseline_bytes_recv = np.random.normal(2500, 1000, 200)
        baseline_pkts = np.random.normal(10, 3, 200)
        baseline_src_ports = np.random.uniform(32768, 65535, 200)
        baseline_dst_ports = np.random.choice([80, 443, 53, 123, 22], 200)

        X_baseline = np.column_stack([
            np.clip(baseline_bytes_sent, 50, 5000),
            np.clip(baseline_bytes_recv, 100, 20000),
            np.clip(baseline_pkts, 1, 50),
            baseline_src_ports,
            baseline_dst_ports
        ])

        self.model.fit(X_baseline)
        self.is_fitted = True

    def predict_anomaly(self, flow: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Predicts if flow is an anomaly.
        Returns (is_anomaly: bool, anomaly_score: float in range [0.0, 1.0]).
        """
        if not self.is_fitted or self.model is None:
            return False, 0.0

        vector = np.array([self._extract_feature_vector(flow)])
        raw_score = float(self.model.score_samples(vector)[0])
        pred = int(self.model.predict(vector)[0])

        # Normalize score into [0.0, 1.0] where 1.0 is extremely anomalous
        # score_samples returns negative values (lower = more anomalous)
        anomaly_score = max(0.0, min(1.0, round((0.5 - raw_score), 3)))
        is_anomaly = (pred == -1) and (anomaly_score > 0.65)

        return is_anomaly, anomaly_score

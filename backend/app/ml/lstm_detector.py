"""
LSTM-based Sequential Anomaly Detection Engine for User Activity Analysis.
Models temporal dependencies in user action streams.
Detects out-of-order execution, privilege escalations, and sudden behavioural drifts.
"""

import numpy as np
import os

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "saved_models")
os.makedirs(MODEL_DIR, exist_ok=True)
LSTM_MODEL_PATH = os.path.join(MODEL_DIR, "lstm_model.pt")

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

if TORCH_AVAILABLE:
    class LSTMSeqModel(nn.Module):
        def __init__(self, input_dim: int, hidden_dim: int = 32, num_layers: int = 1):
            super().__init__()
            self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers=num_layers, batch_first=True)
            self.decoder = nn.Sequential(
                nn.Linear(hidden_dim, 16),
                nn.ReLU(),
                nn.Linear(16, input_dim)
            )

        def forward(self, x):
            lstm_out, _ = self.lstm(x)
            # Reconstruct sequence
            recon = self.decoder(lstm_out)
            return recon

class LSTMSequenceDetector:
    def __init__(self, input_dim: int = 7, hidden_dim: int = 32, sequence_length: int = 5):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.sequence_length = sequence_length
        self.is_trained = False
        self.model = None
        if TORCH_AVAILABLE:
            self.model = LSTMSeqModel(input_dim, hidden_dim)

    def fit(self, sequences: np.ndarray, epochs: int = 15, lr: float = 0.005):
        """Train LSTM sequence model on user activity sequences."""
        if len(sequences) < 3:
            raise ValueError(f"Insufficient sequential data: need at least 3 sequence windows of length {self.sequence_length}")

        if TORCH_AVAILABLE and self.model is not None:
            optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
            criterion = nn.MSELoss()
            X_tensor = torch.tensor(sequences, dtype=torch.float32)

            self.model.train()
            for epoch in range(epochs):
                optimizer.zero_grad()
                output = self.model(X_tensor)
                loss = criterion(output, X_tensor)
                loss.backward()
                optimizer.step()

            self.is_trained = True
            torch.save(self.model.state_dict(), LSTM_MODEL_PATH)
        else:
            # Mathematical sequence variance estimation
            self.is_trained = True
        return self

    def predict_anomaly_scores(self, sequences: np.ndarray) -> np.ndarray:
        """
        Compute reconstruction error or sequence deviation per sample window.
        Returns normalized scores in [0, 1].
        """
        if len(sequences) == 0:
            return np.array([])

        if TORCH_AVAILABLE and self.model is not None:
            if not self.is_trained and os.path.exists(LSTM_MODEL_PATH):
                self.model.load_state_dict(torch.load(LSTM_MODEL_PATH))
                self.is_trained = True

            self.model.eval()
            with torch.no_grad():
                X_tensor = torch.tensor(sequences, dtype=torch.float32)
                recon = self.model(X_tensor)
                errors = torch.mean((recon - X_tensor) ** 2, dim=[1, 2]).numpy()
        else:
            # Sequential difference heuristic
            diffs = np.diff(sequences, axis=1)
            errors = np.mean(np.abs(diffs), axis=(1, 2))

        # Normalize
        min_e = np.min(errors)
        max_e = np.max(errors)
        if max_e - min_e > 1e-6:
            return (errors - min_e) / (max_e - min_e)
        return np.full_like(errors, 0.45)

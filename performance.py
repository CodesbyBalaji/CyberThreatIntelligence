
import time
import json
import os
from datetime import datetime
import statistics
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PerformanceMonitor:
    def __init__(self, metrics_file="data/performance_metrics.json"):
        self.metrics_file = metrics_file
        self.metrics = self._load_metrics()

    def _load_metrics(self):
        if os.path.exists(self.metrics_file):
            try:
                with open(self.metrics_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading metrics: {e}")
                return {}
        return {}

    def save_metrics(self):
        try:
            os.makedirs(os.path.dirname(self.metrics_file), exist_ok=True)
            with open(self.metrics_file, 'w') as f:
                json.dump(self.metrics, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving metrics: {e}")

    def record_latency(self, operation_type, duration_seconds, metadata=None):
        """Record the duration of an operation."""
        if operation_type not in self.metrics:
            self.metrics[operation_type] = []
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'duration': duration_seconds,
            'metadata': metadata or {}
        }
        self.metrics[operation_type].append(entry)
        
        # Keep last 1000 entries per operation to avoid unlimited growth
        if len(self.metrics[operation_type]) > 1000:
            self.metrics[operation_type] = self.metrics[operation_type][-1000:]
            
        self.save_metrics()

    def get_statistics(self, operation_type):
        """Get summary statistics for an operation type."""
        if operation_type not in self.metrics or not self.metrics[operation_type]:
            return None
        
        durations = [m['duration'] for m in self.metrics[operation_type]]
        count = len(durations)
        
        stats = {
            'count': count,
            'avg_latency': statistics.mean(durations),
            'min_latency': min(durations),
            'max_latency': max(durations),
            'last_latency': durations[-1]
        }
        
        # Calculate P95 if enough data points
        if count >= 20:
            try:
                stats['p95_latency'] = statistics.quantiles(durations, n=20)[18]
            except:
                stats['p95_latency'] = max(durations)
        else:
            stats['p95_latency'] = max(durations)
            
        return stats

    def get_all_metrics(self):
        return self.metrics

# Global instance
monitor = PerformanceMonitor()

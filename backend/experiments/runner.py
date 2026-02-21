import uuid
import json
import os
from datetime import datetime
from backend.adversarial.run_attacks import run_redteam_scenario
import pandas as pd

class ExperimentRunner:
    """
    Orchestrates ablations (e.g., Node2Vec vs GraphSAGE) and measures
    the defense gain natively inside the pipeline.
    """
    def __init__(self, output_dir: str = 'experiments/'):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def trigger_experiment(self, baseline_df: pd.DataFrame, attack_type: str, target: str, intensity: float):
        run_id = f"run_{uuid.uuid4().hex[:8]}"
        run_path = os.path.join(self.output_dir, run_id)
        os.makedirs(run_path, exist_ok=True)
        
        # 1. Inject Attack
        poisoned_data = run_redteam_scenario(baseline_df, attack_type, target, intensity=intensity)
        
        # 2. Run Inference Loop (Mocked)
        # y_true = poisoned_data['is_malicious']
        # y_pred = model(poisoned_data)
        
        # 3. Calculate metrics using evaluation.metrics
        # report = generate_report(y_true, y_pred)
        
        report = {
            "experiment_id": run_id,
            "timestamp": datetime.utcnow().isoformat(),
            "attack_type": attack_type,
            "target": target,
            "intensity": intensity,
            "metrics": {
                "asr": 0.12, # mock value
                "pr_auc": 0.89, # mock value
                "roc_auc": 0.94 # mock value
            }
        }
        
        # Save artifact JSON to disk for the UI to parse
        with open(os.path.join(run_path, 'metrics.json'), 'w') as f:
            json.dump(report, f, indent=4)
            
        print(f"Experiment {run_id} completed and saved.")
        return report

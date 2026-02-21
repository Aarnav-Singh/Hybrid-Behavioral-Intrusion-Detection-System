import pandas as pd
from typing import str

from backend.adversarial.dns_tunneling import DNSTunnelingAttack
from backend.adversarial.graph_poisoning import GraphPoisoningAttack
from backend.adversarial.beacon_evasion import BeaconEvasionAttack
from backend.adversarial.feature_perturbation import FeaturePerturbationAttack

def run_redteam_scenario(df: pd.DataFrame, attack_type: str, target_ip: str, **kwargs) -> pd.DataFrame:
    """
    Harness for injecting synthetic red-team evaluation data into the streaming dataframe.
    """
    attacks = {
        'dns_tunneling': DNSTunnelingAttack,
        'graph_poisoning': GraphPoisoningAttack,
        'beacon_evasion': BeaconEvasionAttack,
        'feature_perturbation': FeaturePerturbationAttack
    }
    
    if attack_type not in attacks:
        raise ValueError(f"Unknown attack type: {attack_type}")
        
    attacker = attacks[attack_type](target_ip=target_ip, **kwargs)
    poisoned_df = attacker.inject(df)
    
    return poisoned_df

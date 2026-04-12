import yaml
import os

class Config:
    def __init__(self, config_path="config.yaml"):
        # Look for config in the same directory as this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(current_dir, config_path)
        
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Config file not found at {full_path}. Please create it from config.yaml.example")
            
        with open(full_path, 'r') as f:
            self._config = yaml.safe_load(f)
            
    def get_phone(self, key):
        return self._config.get('phone_numbers', {}).get(key)
        
    def get_device(self, key):
        return self._config.get('devices', {}).get(key)
        
    @property
    def active_pair(self):
        return self._config.get('active_device_pair', 1)

# Singleton instance
try:
    config = Config()
except FileNotFoundError:
    config = None

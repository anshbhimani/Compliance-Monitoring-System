import importlib.util
import yaml

def load_scripts():
    with open("config/scripts_registry.yaml", "r") as file:
        return yaml.safe_load(file)

def load_and_run_script(script_path):
    spec = importlib.util.spec_from_file_location("module.name", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_check()

from utils import load_and_run_script

def generate_report(package_id):
    package = get_package_from_db(package_id)  # Retrieve from database
    results = [load_and_run_script(script["path"]) for script in package["scripts"]]
    return {"package": package["name"], "results": results}

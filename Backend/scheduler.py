from apscheduler.schedulers.background import BackgroundScheduler
from utils import load_and_run_script, load_scripts

def scheduled_check():
    scripts = load_scripts()
    results = [load_and_run_script(script["path"]) for script in scripts if script["enabled"]]
    # Process results, save, or alert

scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_check, 'interval', hours=1)  # Adjustable interval
scheduler.start()

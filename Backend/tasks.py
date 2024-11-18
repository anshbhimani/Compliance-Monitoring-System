from celery import Celery
from app import run_check_script

celery = Celery('tasks', broker='redis://localhost:6379/0')

@celery.task
def scheduled_check(script_name):
    result = run_check_script(script_name)
    # Store result in the database
    return result

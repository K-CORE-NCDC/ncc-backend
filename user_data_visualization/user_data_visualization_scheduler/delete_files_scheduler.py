from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from user_data_visualization.views import DeleteExpiredProjects
import pytz

# Define the South Korean timezone
south_korean_timezone = pytz.timezone('Asia/Seoul')


def start():
    scheduler = BackgroundScheduler()
    delete_projects = DeleteExpiredProjects()

    # Define the trigger to run every day at midnight (00:00) in South Korean time
    trigger = CronTrigger(
        hour=0,
        minute=0,
        second=0,
        timezone=south_korean_timezone,
        day_of_week='*'
    )

    # Schedule the job using the defined trigger
    scheduler.add_job(
        delete_projects.delete_expired_projects_deactivate_users,
        trigger=trigger,
        id="delete_projects_1",
        replace_existing=True
    )

    print('scheduler started...')
    scheduler.start()

# import atexit
# import pytz
# from app.models import SessionDetails
# from apscheduler.schedulers.background import BackgroundScheduler
# from apscheduler.triggers.interval import IntervalTrigger
# from django.contrib.sessions.models import Session
# from django.utils import timezone

# south_korean_timezone = pytz.timezone('Asia/Seoul')

# def start():
#     scheduler = BackgroundScheduler(timezone=south_korean_timezone)

#     trigger = IntervalTrigger(seconds=5)

#     scheduler.add_job(
#         update_session_stats,
#         trigger=trigger,
#         id="update_session_stats",
#         replace_existing=True
#     )

#     print('Scheduler started...')
#     scheduler.start()

#     # Shut down the scheduler when exiting the app

#     atexit.register(scheduler.shutdown)

# def update_session_stats():
#     active_sessions = Session.objects.filter(expire_date__gte=timezone.now())
#     user_ids = [session.get_decoded().get('_auth_user_id') for session in active_sessions]
#     logged_in_users = SessionDetails.objects.filter(user_id__in=user_ids)
#     logged_out_users = SessionDetails.objects.exclude(user_id__in=user_ids)

#     for user in logged_in_users:
#         user.end_time = None
#         user.save()

#     for user in logged_out_users:
#         user.end_time = timezone.now()
#         user.save()

import html
import secrets
import datetime

from flask import request

from Sentinel_api.SentinelSuite.IAM_DB import db
from Sentinel_api.app import app
from Sentinel_api.app.models import LogsModel


def add_to_log(classification, target_route, priority, details, user_id, app_api_key):
    log_id = "LOGS_" + secrets.token_urlsafe()
    time = datetime.datetime.now().isoformat()
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    usr_id = user_id if user_id is not None else "None"
    with app.app_context():
        unauthorized_entry = LogsModel(log_id=log_id, user_id=usr_id, classification=classification,
                                       priority=priority, time=time, target=html.escape(target_route), details=details,
                                       source_ip=client_ip, app_api_key=app_api_key)
        db.session.add(unauthorized_entry)
        db.session.commit()
from Sentinel_api.app import app
from Sentinel_api.app.models import FirewallBlockList


def get_block_list():
    with app.app_context():
        blocked_ips = [entry.block_ip for entry in FirewallBlockList.query.all()]
        return blocked_ips
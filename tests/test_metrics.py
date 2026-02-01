from flask.testing import FlaskClient
from ntrip_caster.web import create_web_manager
from ntrip_caster.database import DatabaseManager
from ntrip_caster.forwarder import get_forwarder
import time

def test_metrics_endpoint() -> None:
    db_manager = DatabaseManager()
    data_forwarder = get_forwarder()
    web_manager = create_web_manager(db_manager, data_forwarder, time.time())
    client = web_manager.app.test_client()

    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"ntrip_active_connections" in response.data
    assert b"ntrip_connections_total" in response.data
    assert b"ntrip_data_throughput_bytes" in response.data

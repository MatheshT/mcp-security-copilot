from datetime import datetime

from app.routes.log_analysis.api import generate_investigation_id


def test_generate_investigation_id_is_unique_for_same_second():
    now = datetime(2026, 10, 3, 19, 19, 15)

    ids = {generate_investigation_id(now) for _ in range(10)}

    assert len(ids) == 10
    assert all(i.startswith("inv_20261003_191915_") for i in ids)

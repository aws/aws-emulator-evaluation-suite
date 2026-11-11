"""get-send-statistics-datapoint-shape."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "get-send-statistics-datapoint-shape"
GROUP = 'sending'
SERVICES = ['ses']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSendStatistics returns a SendDataPoints series whose entries are internally consistent."""
    ses = ctx.client("ses")
    resp = ses.get_send_statistics()
    points = resp.get("SendDataPoints")
    assert isinstance(points, list), f"expected SendDataPoints to be a list, got {type(points)}"

    for point in points:
        assert "Timestamp" in point, f"SendDataPoints entry missing Timestamp: {point}"
        delivery_attempts = point.get("DeliveryAttempts", 0)
        bounces = point.get("Bounces", 0)
        complaints = point.get("Complaints", 0)
        rejects = point.get("Rejects", 0)
        for field, value in (
            ("DeliveryAttempts", delivery_attempts),
            ("Bounces", bounces),
            ("Complaints", complaints),
            ("Rejects", rejects),
        ):
            assert isinstance(value, int) and value >= 0, (
                f"expected non-negative integer {field}, got {value!r} in {point}"
            )
        assert bounces <= delivery_attempts, (
            f"Bounces cannot exceed DeliveryAttempts in a datapoint: {point}"
        )
        assert complaints <= delivery_attempts, (
            f"Complaints cannot exceed DeliveryAttempts in a datapoint: {point}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

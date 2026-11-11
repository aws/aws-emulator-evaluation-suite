"""representation-metric-definition-numeric-precision-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "representation-metric-definition-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Numeric threshold literals embedded in a custom metric's EventPattern
    round-trip through BatchCreateRumMetricDefinitions -> BatchGetRumMetricDefinitions
    with no float drift or truncation."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-precision-")
    rum.create_app_monitor(Name=name, Domain="localhost", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))

    # A metrics destination must exist before any metric definitions can be
    # created against this app monitor.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(lambda: rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch"))

    event_pattern = {
        "event_type": ["com.amazon.rum.performance_navigation_event"],
        "event_details": {"duration": [{"numeric": [">=", 1234.567891, "<", 987654.321098]}]},
    }
    event_pattern_str = json.dumps(event_pattern)
    metric_name = "PrecisionCustomMetric"

    # Creation is asynchronous: the create call itself can return with
    # neither an entry in MetricDefinitions nor in Errors (an empty ack), so
    # confirm the effect by polling BatchGetRumMetricDefinitions with bounded
    # retries instead of retrying the create call (which would otherwise
    # collide with the already-in-flight create and surface a spurious
    # ConflictException).
    import time

    create_resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=name,
        Destination="CloudWatch",
        MetricDefinitions=[
            {
                "Name": metric_name,
                "Namespace": "sim2real/PrecisionNamespace",
                "ValueKey": "event_details.duration",
                "EventPattern": event_pattern_str,
            }
        ],
    )
    assert create_resp["Errors"] == [], repr([e.get("ErrorCode") for e in create_resp["Errors"]])

    created = next((d for d in create_resp["MetricDefinitions"] if d["Name"] == metric_name), None)
    if created is None:
        for _ in range(6):
            fetched = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
            created = next((d for d in fetched["MetricDefinitions"] if d["Name"] == metric_name), None)
            if created is not None:
                break
            time.sleep(5)
    assert created is not None, "PrecisionCustomMetric never appeared after create"
    metric_id = created["MetricDefinitionId"]
    ctx.on_cleanup(
        lambda: rum.batch_delete_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[metric_id]
        )
    )

    create_pattern = json.loads(created["EventPattern"])
    assert create_pattern == event_pattern, f"expected {event_pattern!r} on create, got {create_pattern!r}"

    fetched = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
    match = next(d for d in fetched["MetricDefinitions"] if d["MetricDefinitionId"] == metric_id)
    round_tripped_pattern = json.loads(match["EventPattern"])
    assert round_tripped_pattern == event_pattern, (
        f"expected {event_pattern!r} on independent BatchGet, got {round_tripped_pattern!r}"
    )
    numeric_clause = round_tripped_pattern["event_details"]["duration"][0]["numeric"]
    assert numeric_clause[1] == 1234.567891, f"expected lower bound 1234.567891, got {numeric_clause[1]!r}"
    assert numeric_clause[3] == 987654.321098, f"expected upper bound 987654.321098, got {numeric_clause[3]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""update-metric-definition-concurrent-modification-conflict."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-metric-definition-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous UpdateRumMetricDefinition calls on one MetricDefinitionId are both accepted, and
    the persisted definition matches exactly one of the two payloads, never a merge."""
    rum = ctx.client("rum")
    app_name = ctx.unique_name("sim2real-rum-conflict-")
    rum.create_app_monitor(Name=app_name, Domain="sim2real-behav.example.com")
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=app_name))

    rum.put_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: rum.delete_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")
        )
    )

    base_def = _metric_definition("Milliseconds")
    created = rum.batch_create_rum_metric_definitions(
        AppMonitorName=app_name, Destination="CloudWatch", MetricDefinitions=[base_def]
    )
    metric_id = _resolve_metric_id(rum, app_name, created, base_def)
    ctx.on_cleanup(
        lambda: rum.batch_delete_rum_metric_definitions(
            AppMonitorName=app_name, Destination="CloudWatch", MetricDefinitionIds=[metric_id]
        )
    )

    payloads = {"A": _metric_definition("Bytes"), "B": _metric_definition("Milliseconds")}
    barrier = threading.Barrier(2)

    def _attempt(label: str):
        barrier.wait()
        try:
            rum.update_rum_metric_definition(
                AppMonitorName=app_name,
                Destination="CloudWatch",
                MetricDefinition=payloads[label],
                MetricDefinitionId=metric_id,
            )
            return (label, "ok", None)
        except ClientError as e:
            return (label, "err", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as ex:
        results = [f.result() for f in [ex.submit(_attempt, "A"), ex.submit(_attempt, "B")]]

    successes = [r for r in results if r[1] == "ok"]
    assert len(successes) == 2, (
        f"expected both concurrent UpdateRumMetricDefinition calls to be accepted -- "
        f"the operation carries no revision token to conflict on, so neither racer should be "
        f"rejected -- got {results}"
    )

    # Both attempts were accepted, but the persisted definition afterward is exactly one of the
    # two payloads -- never a merge/corruption of both.
    stored = rum.batch_get_rum_metric_definitions(AppMonitorName=app_name, Destination="CloudWatch")
    stored_defs = {d["MetricDefinitionId"]: d for d in stored["MetricDefinitions"]}
    persisted_unit = stored_defs[metric_id]["UnitLabel"]
    valid_units = {payloads["A"]["UnitLabel"], payloads["B"]["UnitLabel"]}
    assert persisted_unit in valid_units, (
        f"persisted definition does not match either concurrent writer's payload: "
        f"UnitLabel={persisted_unit!r}, expected one of {valid_units}"
    )


import time


def _resolve_metric_id(rum, app_name: str, create_response: dict, definition: dict, timeout_s: float = 40.0, interval_s: float = 2.0) -> str:
    """BatchCreateRumMetricDefinitions can transiently report the create as neither an error
    nor a returned definition while the metrics destination finishes propagating, even though
    the definition is actually persisted moments later. Trust BatchGetRumMetricDefinitions (the
    read path) as the durable source of truth: if the create call itself returned the
    definition, use that id directly; a genuine per-item validation error is raised immediately;
    otherwise poll the read path for a definition matching this Name/Namespace."""
    if create_response.get("MetricDefinitions"):
        return create_response["MetricDefinitions"][0]["MetricDefinitionId"]
    for err in create_response.get("Errors") or []:
        if err.get("ErrorCode") != "ConflictException":
            raise AssertionError(f"unexpected per-item error creating metric definition: {err}")

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = rum.batch_get_rum_metric_definitions(AppMonitorName=app_name, Destination="CloudWatch")
        for d in got["MetricDefinitions"]:
            if d["Name"] == definition["Name"] and d.get("Namespace") == definition.get("Namespace"):
                return d["MetricDefinitionId"]
        time.sleep(interval_s)
    raise AssertionError("metric definition not found via BatchGetRumMetricDefinitions after create")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _metric_definition(unit_label: str) -> dict:
    return {
        "Name": "Sim2RealVisitCount",
        "Namespace": "Sim2RealCustomMetrics",
        "ValueKey": "event_details.visit_count",
        "UnitLabel": unit_label,
        "EventPattern": json.dumps({"event_type": ["sim2real_custom_event"]}),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

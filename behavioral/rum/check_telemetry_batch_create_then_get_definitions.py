"""telemetry-batch-create-then-get-definitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-batch-create-then-get-definitions"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchCreateRumMetricDefinitions followed by BatchGetRumMetricDefinitions returns exactly
    the created definitions with their configured event pattern and namespace, and a subsequent
    BatchDeleteRumMetricDefinitions removes them from a later BatchGet."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(Name=name, Domain="example.com", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    # A metrics destination must exist before metric definitions can target it.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(lambda: _safe_delete_destination(ctx, name))

    extended_pattern = json.dumps({"event_type": ["com.amazon.rum.js_error_event"]})
    custom_pattern = json.dumps({"event_type": ["com.amazon.rum.custom_event"]})
    extended_def = {"Name": "JsErrorCount", "EventPattern": extended_pattern}
    custom_def = {
        "Name": "CustomLatencyMetric",
        "Namespace": "SimparityBehavioral",
        "EventPattern": custom_pattern,
        "ValueKey": "event_details.duration",
    }

    # PutRumMetricsDestination is eventually consistent: BatchCreate issued immediately after
    # it can come back 200 with the definitions truly created but the response body itself
    # showing empty MetricDefinitions/Errors. Re-issuing the create on such an "empty" response
    # risks a spurious ConflictException against a definition the first call already made, so
    # create exactly once, tolerate ConflictException as evidence of a successful create, and
    # resolve the definitive ids via a bounded poll of BatchGet.
    create_resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch", MetricDefinitions=[extended_def, custom_def]
    )
    unexpected_errors = [e for e in create_resp["Errors"] if e["ErrorCode"] != "ConflictException"]
    assert not unexpected_errors, f"expected no BatchCreate errors, got {unexpected_errors}"

    wanted_names = {"JsErrorCount", "CustomLatencyMetric"}
    fetched = _poll_until(
        probe=lambda: rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
            "MetricDefinitions"
        ],
        predicate=lambda defs: wanted_names.issubset({d["Name"] for d in defs}),
    )
    fetched_by_name = {d["Name"]: d for d in fetched}

    assert "JsErrorCount" in fetched_by_name, f"JsErrorCount missing from BatchGet: {sorted(fetched_by_name)}"
    assert fetched_by_name["JsErrorCount"]["EventPattern"] == extended_pattern, (
        f"expected EventPattern {extended_pattern!r}, got "
        f"{fetched_by_name['JsErrorCount']['EventPattern']!r}"
    )

    assert "CustomLatencyMetric" in fetched_by_name, (
        f"CustomLatencyMetric missing from BatchGet: {sorted(fetched_by_name)}"
    )
    custom_fetched = fetched_by_name["CustomLatencyMetric"]
    assert custom_fetched["EventPattern"] == custom_pattern, (
        f"expected EventPattern {custom_pattern!r}, got {custom_fetched['EventPattern']!r}"
    )
    assert custom_fetched["Namespace"] == "SimparityBehavioral", (
        f"expected Namespace 'SimparityBehavioral', got {custom_fetched['Namespace']!r}"
    )
    assert custom_fetched["ValueKey"] == "event_details.duration", (
        f"expected ValueKey 'event_details.duration', got {custom_fetched['ValueKey']!r}"
    )

    created_ids = [fetched_by_name[n]["MetricDefinitionId"] for n in wanted_names]
    ctx.on_cleanup(lambda: _safe_batch_delete(ctx, name, created_ids))

    rum.batch_delete_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=created_ids
    )
    remaining_ids = {
        d["MetricDefinitionId"]
        for d in rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
            "MetricDefinitions"
        ]
    }
    assert not (set(created_ids) & remaining_ids), (
        f"deleted definitions {created_ids} still present in BatchGet: {remaining_ids}"
    )


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _safe_delete_app_monitor(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_destination(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_batch_delete(ctx, name: str, ids: list) -> None:
    rum = ctx.client("rum")
    try:
        rum.batch_delete_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=ids
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

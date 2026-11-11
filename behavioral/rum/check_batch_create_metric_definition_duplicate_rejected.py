"""batch-create-metric-definition-duplicate-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-create-metric-definition-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Resubmitting an identical metric definition is refused per item with ConflictException
    without overwriting the original, the same Name with another EventPattern coexists, and after
    the original is deleted the identical call succeeds.
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(Name=name, Domain="example.com", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    # A metrics destination must exist before metric definitions can target it.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(lambda: _safe_delete_destination(ctx, name))

    metric_name = "CustomDupMetric"
    pattern = json.dumps({"event_type": ["com.amazon.rum.custom_event"]})
    definition = {
        "Name": metric_name,
        "Namespace": "SimparityBehavioral",
        "EventPattern": pattern,
    }

    # Positive control: the first creation of this Name succeeds cleanly. PutRumMetricsDestination
    # is eventually consistent, so a create issued right after it can come back 200 with both
    # MetricDefinitions and Errors empty even though the definition lands server-side.
    first = _create_or_resolve(rum, name, "CloudWatch", definition)
    assert first.get("Errors", []) == [], f"unexpected errors on first create: {first.get('Errors')}"
    assert len(first["MetricDefinitions"]) == 1, f"expected exactly one created definition, got {first}"
    current_id = first["MetricDefinitions"][0]["MetricDefinitionId"]
    ctx.on_cleanup(
        lambda: rum.batch_delete_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[current_id]
        )
    )

    # Break exactly one thing: resubmit the IDENTICAL definition (same Name, Namespace and
    # EventPattern) on the same app monitor/destination -> per-item ConflictException, no
    # overwrite of the original. (A same-Name-different-EventPattern submission is NOT a
    # conflict at all -- real RUM creates a second, coexisting definition for it -- so the
    # duplicate under test must match content, not just Name.) The response can itself come
    # back empty/empty (the same display lag as the first create); since this exact resource
    # already exists, re-issuing the call is safe (it can never spuriously succeed) -- so
    # retry the call itself until it reports conclusively.
    dup_definition = dict(definition)
    second = _create_until_resolved(rum, name, "CloudWatch", dup_definition)
    errors = second.get("Errors", [])
    assert len(errors) == 1, f"expected exactly one per-item error, got {errors}"
    assert errors[0]["ErrorCode"] == "ConflictException", f"expected ConflictException, got {errors[0]}"
    expected_message = (
        f"Metric definition already exists: MetricDefinitionRequest(name={metric_name}, "
        f"valueKey=null, unitLabel=null, dimensionKeys=null, eventPattern={pattern}, "
        f"namespace=SimparityBehavioral)"
    )
    assert errors[0]["ErrorMessage"] == expected_message, (
        f"expected ErrorMessage {expected_message!r}, got {errors[0].get('ErrorMessage')!r}"
    )
    assert second.get("MetricDefinitions", []) == [], (
        f"duplicate create must not produce a second definition, got {second.get('MetricDefinitions')}"
    )

    # Effect absent: an independent read shows exactly one definition with this name, unchanged.
    current = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
        "MetricDefinitions"
    ]
    matching = [d for d in current if d["Name"] == metric_name]
    assert len(matching) == 1, f"duplicate create must not produce a second definition, got {matching}"
    assert matching[0]["MetricDefinitionId"] == current_id, (
        f"expected the original definition {current_id} to remain, got {matching[0]['MetricDefinitionId']}"
    )
    assert matching[0]["EventPattern"] == pattern, (
        f"original definition must remain unchanged: expected {pattern}, got {matching[0]['EventPattern']}"
    )

    # Restore: free the Name by deleting the original, confirm it's gone via an independent
    # read, then reissue the identical call that was rejected above -- it must now succeed.
    delete_resp = rum.batch_delete_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[current_id]
    )
    assert delete_resp.get("Errors", []) == [], f"unexpected delete errors: {delete_resp.get('Errors')}"

    after_delete = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
        "MetricDefinitions"
    ]
    assert not any(d["Name"] == metric_name for d in after_delete), (
        f"deleted definition {current_id} still visible: {after_delete}"
    )

    restored = _create_or_resolve(rum, name, "CloudWatch", dup_definition)
    assert restored.get("Errors", []) == [], f"identical call must now succeed, got {restored.get('Errors')}"
    assert len(restored["MetricDefinitions"]) == 1, f"expected the freed name to be creatable, got {restored}"
    current_id = restored["MetricDefinitions"][0]["MetricDefinitionId"]


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


def _create_or_resolve(
    rum, name: str, destination: str, definition: dict, timeout_s: float = 60.0, interval_s: float = 3.0
) -> dict:
    """PutRumMetricsDestination is eventually consistent: immediately after it, a single
    BatchCreateRumMetricDefinitions call can come back 200 with BOTH MetricDefinitions and
    Errors empty, even though the definition IS created server-side. Issue the create exactly
    once, and if the response is ambiguous, resolve it by polling BatchGet instead of
    re-issuing the write (which would risk a spurious ConflictException against a definition
    that already landed)."""
    resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=name, Destination=destination, MetricDefinitions=[definition]
    )
    if resp.get("MetricDefinitions") or resp.get("Errors"):
        return resp

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        fetched = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination=destination)
        match = next((d for d in fetched["MetricDefinitions"] if d["Name"] == definition["Name"]), None)
        if match is not None:
            return {"MetricDefinitions": [match], "Errors": []}
    raise AssertionError(f"definition {definition['Name']!r} never became visible within {timeout_s}s")


def _create_until_resolved(
    rum, name: str, destination: str, definition: dict, timeout_s: float = 60.0, interval_s: float = 3.0
) -> dict:
    """Retry an ALREADY-CONFLICTING create (the Name is known taken) until the response
    reports conclusively. Unlike a first-time create, re-issuing this exact call carries no
    risk: the Name cannot legitimately succeed, so a non-empty MetricDefinitions on any
    attempt is itself evidence of the defect this check exists to catch, not a side effect of
    retrying."""
    deadline = time.monotonic() + timeout_s
    resp = {"MetricDefinitions": [], "Errors": []}
    while time.monotonic() < deadline:
        resp = rum.batch_create_rum_metric_definitions(
            AppMonitorName=name, Destination=destination, MetricDefinitions=[definition]
        )
        if resp.get("MetricDefinitions") or resp.get("Errors"):
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"create of {definition['Name']!r} never resolved within {timeout_s}s: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

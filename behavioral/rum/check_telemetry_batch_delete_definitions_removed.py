"""telemetry-batch-delete-definitions-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-batch-delete-definitions-removed"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDeleteRumMetricDefinitions removes definitions such that a subsequent
    BatchGetRumMetricDefinitions no longer returns them, and a second delete of the
    same id is rejected as not-found rather than silently succeeding again."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(Name=name, Domain="example.com", Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    # A metrics destination must exist before metric definitions can target it.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(lambda: _safe_delete_destination(ctx, name))
    _wait_for_destination(rum, name)

    pattern = json.dumps({"event_type": ["com.amazon.rum.custom_event"]})
    created, errs = _create_with_retry(
        rum,
        name,
        {
            "Name": "ToBeDeletedMetric",
            "Namespace": "SimparityBehavioral",
            "EventPattern": pattern,
        },
    )
    assert not errs, f"unexpected create errors: {errs!r}"
    assert len(created) == 1, f"expected exactly one definition created, got {created!r}"
    definition_id = created[0]["MetricDefinitionId"]

    before = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
        "MetricDefinitions"
    ]
    assert any(d["MetricDefinitionId"] == definition_id for d in before), (
        f"newly created definition {definition_id} missing from BatchGet: {before!r}"
    )

    delete_result = rum.batch_delete_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[definition_id]
    )
    assert delete_result.get("Errors", []) == [], (
        f"unexpected delete errors: {delete_result.get('Errors')!r}"
    )

    after = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
        "MetricDefinitions"
    ]
    assert not any(d["MetricDefinitionId"] == definition_id for d in after), (
        "deleted metric definition must not still be returned by BatchGetRumMetricDefinitions"
    )

    redelete_errs = rum.batch_delete_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[definition_id]
    ).get("Errors", [])
    assert (
        len(redelete_errs) == 1 and redelete_errs[0].get("MetricDefinitionId") == definition_id
    ), f"expected a single not-found error re-deleting the gone id, got {redelete_errs!r}"
    assert redelete_errs[0].get("ErrorCode") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting a gone id, got {redelete_errs[0]!r}"
    )
    assert redelete_errs[0].get("ErrorMessage") == "Resource not found", (
        f"expected ErrorMessage 'Resource not found' re-deleting a gone id, got {redelete_errs[0]!r}"
    )


def _wait_for_destination(rum, name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """PutRumMetricsDestination is eventually consistent: BatchCreateRumMetricDefinitions
    silently no-ops (empty MetricDefinitions/Errors) if the destination isn't visible yet."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dests = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
        if any(d["Destination"] == "CloudWatch" for d in dests):
            return
        time.sleep(interval_s)
    raise AssertionError(f"destination for {name} never became visible within {timeout_s}s")


def _create_with_retry(
    rum, name: str, metric_definition: dict, timeout_s: float = 30.0, interval_s: float = 2.0
):
    """A BatchCreate call can transiently return empty MetricDefinitions/Errors right after
    the destination becomes visible but before creation is fully applied -- poll (without
    resending the write) until the backend actually reports created/errored items. The SDK's
    own transparent retry-on-throttle can also resend an already-applied BatchCreate, so a
    definition can come back as ConflictException even though an earlier (unobserved) attempt
    truly created it -- resolve that by looking it up via BatchGet rather than treating it as
    a real error."""
    deadline = time.monotonic() + timeout_s
    created: list = []
    errs: list = []
    while time.monotonic() < deadline:
        resp = rum.batch_create_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitions=[metric_definition]
        )
        created = resp.get("MetricDefinitions", [])
        errs = resp.get("Errors", [])
        if created or errs:
            return _resolve_conflicts(rum, name, created, errs)
        time.sleep(interval_s)
    return created, errs


def _resolve_conflicts(rum, name: str, created: list, errs: list) -> tuple:
    resolved_created = list(created)
    resolved_errs = []
    for e in errs:
        if e.get("ErrorCode") == "ConflictException":
            d = e.get("MetricDefinition", {}) or {}
            got = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
            match = next(
                (
                    g
                    for g in got["MetricDefinitions"]
                    if g["Name"] == d.get("Name") and g.get("Namespace") == d.get("Namespace")
                ),
                None,
            )
            if match is not None:
                resolved_created.append(match)
                continue
        resolved_errs.append(e)
    return resolved_created, resolved_errs


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""batch-delete-metric-definitions-partial-errors."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-metric-definitions-partial-errors"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDeleteRumMetricDefinitions given a mix of one valid and one unknown
    metric-definition id deletes the valid one and reports a per-item error for the
    unknown one, instead of failing the whole batch or silently ignoring the bad id."""
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)
    rum.put_rum_metrics_destination(AppMonitorName=app["name"], Destination="CloudWatch")

    metric_definitions = [
        {
            "Name": "sim2real_js_error_count",
            "Namespace": "sim2real/CustomMetrics",
            "EventPattern": json.dumps({"event_type": ["com.amazon.rum.js_error_event"]}),
        },
        {
            "Name": "sim2real_session_count",
            "Namespace": "sim2real/CustomMetrics",
            "EventPattern": json.dumps(
                {"event_type": ["com.amazon.rum.session_start_event"]}
            ),
        },
    ]

    # PutRumMetricsDestination is eventually consistent: immediately following it,
    # BatchCreateRumMetricDefinitions can return 200 with the definitions actually
    # created, but with the response body ITSELF showing empty MetricDefinitions and
    # empty Errors (a display lag distinct from the destination-propagation lag). So
    # do not re-issue the create on an "empty" response -- that risks a spurious
    # ConflictException against a definition that in fact was already created by the
    # first call. Issue the create exactly once, tolerate ConflictException as
    # evidence of a (possibly earlier) successful create, then resolve the definitive
    # MetricDefinitionIds via a bounded poll of BatchGetRumMetricDefinitions.
    create_resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=app["name"],
        Destination="CloudWatch",
        MetricDefinitions=metric_definitions,
    )
    _errs = create_resp.get("Errors") or []
    _unexpected = [e for e in _errs if e.get("ErrorCode") != "ConflictException"]
    assert not _unexpected, "codes=" + ",".join(str(e.get("ErrorCode")) for e in _unexpected)

    wanted_names = {"sim2real_js_error_count", "sim2real_session_count"}
    get_resp = _poll_until(
        probe=lambda: rum.batch_get_rum_metric_definitions(
            AppMonitorName=app["name"], Destination="CloudWatch"
        ),
        predicate=lambda resp: wanted_names.issubset(
            {d["Name"] for d in resp["MetricDefinitions"]}
        ),
        timeout_s=60.0,
        interval_s=3.0,
    )
    ids_by_name = {
        d["Name"]: d["MetricDefinitionId"]
        for d in get_resp["MetricDefinitions"]
        if d["Name"] in wanted_names
    }
    id_to_delete = ids_by_name["sim2real_js_error_count"]
    id_to_keep = ids_by_name["sim2real_session_count"]
    bogus_id = "does-not-exist-0000000000000000"

    ctx.on_cleanup(
        lambda: _safe_batch_delete(rum, app["name"], [id_to_delete, id_to_keep])
    )

    delete_resp = rum.batch_delete_rum_metric_definitions(
        AppMonitorName=app["name"],
        Destination="CloudWatch",
        MetricDefinitionIds=[id_to_delete, bogus_id],
    )

    assert delete_resp["MetricDefinitionIds"] == [id_to_delete], (
        f"expected only {id_to_delete!r} to succeed, got {delete_resp['MetricDefinitionIds']!r}"
    )
    assert len(delete_resp["Errors"]) == 1, (
        f"expected exactly 1 per-item error, got {len(delete_resp['Errors'])}: {delete_resp['Errors']!r}"
    )
    error = delete_resp["Errors"][0]
    assert error["MetricDefinitionId"] == bogus_id, (
        f"expected the error to name the bogus id {bogus_id!r}, got {error['MetricDefinitionId']!r}"
    )
    assert error["ErrorCode"] == "ResourceNotFoundException", (
        f"expected ErrorCode=ResourceNotFoundException for the bogus id, got {error['ErrorCode']!r}"
    )
    assert error["ErrorMessage"] == "Resource not found", (
        f"expected ErrorMessage='Resource not found' for the bogus id, got {error.get('ErrorMessage')!r}"
    )

    remaining = rum.batch_get_rum_metric_definitions(
        AppMonitorName=app["name"], Destination="CloudWatch"
    )["MetricDefinitions"]
    remaining_ids = {d["MetricDefinitionId"] for d in remaining}
    assert id_to_delete not in remaining_ids, (
        f"deleted definition {id_to_delete!r} still present in BatchGet: {remaining_ids!r}"
    )
    assert id_to_keep in remaining_ids, (
        f"sibling definition {id_to_keep!r} incorrectly removed; remaining={remaining_ids!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


def _safe_batch_delete(rum, app_monitor_name, metric_definition_ids):
    try:
        rum.batch_delete_rum_metric_definitions(
            AppMonitorName=app_monitor_name,
            Destination="CloudWatch",
            MetricDefinitionIds=metric_definition_ids,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


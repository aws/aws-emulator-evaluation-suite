"""update-rum-metric-definition-concurrent-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-rum-metric-definition-concurrent-conflict"
GROUP = "concurrency"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two racing UpdateRumMetricDefinition calls on one MetricDefinitionId each succeed or fail with
    ConflictException, at least one succeeds, and the stored DimensionKeys equal exactly one of the two
    submitted maps, never a merge."""
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)
    rum.put_rum_metrics_destination(AppMonitorName=app["name"], Destination="CloudWatch")

    base_definition = {
        "Name": "sim2real_js_error_count",
        "Namespace": "sim2real/CustomMetrics",
        "EventPattern": json.dumps(
            {
                "event_type": ["com.amazon.rum.js_error_event"],
                "metadata": {
                    "browserName": ["Chrome", "Firefox", "Safari"],
                    "countryCode": ["US", "JP", "DE"],
                },
            }
        ),
    }

    # PutRumMetricsDestination is eventually consistent: immediately following it,
    # BatchCreateRumMetricDefinitions can return 200 with the definition actually
    # created, but with the response body ITSELF showing empty MetricDefinitions and
    # empty Errors (a display lag distinct from the destination-propagation lag). So
    # do not re-issue the create on an "empty" response -- that risks a spurious
    # ConflictException against a definition that in fact was already created by the
    # first call. Issue the create exactly once, tolerate ConflictException as
    # evidence of a (possibly earlier) successful create, then resolve the definitive
    # MetricDefinitionId via a bounded poll of BatchGetRumMetricDefinitions.
    create_resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=app["name"],
        Destination="CloudWatch",
        MetricDefinitions=[base_definition],
    )
    _errs = create_resp.get("Errors") or []
    _unexpected = [e for e in _errs if e.get("ErrorCode") != "ConflictException"]
    assert not _unexpected, "codes=" + ",".join(str(e.get("ErrorCode")) for e in _unexpected)

    get_after_create = _poll_until(
        probe=lambda: rum.batch_get_rum_metric_definitions(
            AppMonitorName=app["name"], Destination="CloudWatch"
        ),
        predicate=lambda resp: any(
            d["Name"] == base_definition["Name"] for d in resp["MetricDefinitions"]
        ),
        timeout_s=60.0,
        interval_s=3.0,
    )
    metric_definition_id = next(
        d["MetricDefinitionId"]
        for d in get_after_create["MetricDefinitions"]
        if d["Name"] == base_definition["Name"]
    )


    def _cleanup_metric():
        try:
            rum.batch_delete_rum_metric_definitions(
                AppMonitorName=app["name"],
                Destination="CloudWatch",
                MetricDefinitionIds=[metric_definition_id],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_metric)

    variant_a = {**base_definition, "DimensionKeys": {"metadata.browserName": "BrowserName"}}
    variant_b = {**base_definition, "DimensionKeys": {"metadata.countryCode": "CountryCode"}}

    def _update(variant):
        try:
            rum.update_rum_metric_definition(
                AppMonitorName=app["name"],
                Destination="CloudWatch",
                MetricDefinition=variant,
                MetricDefinitionId=metric_definition_id,
            )
            return None
        except ClientError as e:
            return e.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, variant_a), pool.submit(_update, variant_b)]
        results = [f.result() for f in futures]

    # Every racer either wins (None) or loses with exactly ConflictException.
    for code in results:
        assert code is None or code == "ConflictException", f"unexpected code: {code}"
    assert results.count(None) >= 1, "at least one concurrent update must win"

    get_resp = rum.batch_get_rum_metric_definitions(
        AppMonitorName=app["name"], Destination="CloudWatch"
    )
    stored = next(
        d for d in get_resp["MetricDefinitions"] if d["MetricDefinitionId"] == metric_definition_id
    )
    assert stored.get("DimensionKeys") in (
        variant_a["DimensionKeys"],
        variant_b["DimensionKeys"],
    ), "final DimensionKeys must exactly match one submitted payload, not a merge"


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

"""blocked-and-counted-requests-carry-the-webacl-and-rule-dimensions."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "blocked-and-counted-requests-carry-the-webacl-and-rule-dimensions"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "wafv2"]

#: Non-round and mutually distinct, so no single shared counter satisfies two assertions at once.
_N_BLOCKED = 7
_N_COUNTED = 3
_N_QUIET_BLOCKED = 5

_METRIC_BUDGET_S = 600.0
_ENFORCEMENT_BUDGET_S = 180.0
#: Fixed windows, each read every _POLL_S (at least 3 reads).
_ENFORCEMENT_STEADY_S = 10.0
_ABSENCE_HOLD_S = 6.0
_ASSOCIATION_RETRY_BUDGET_S = 240.0
_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/waf/latest/developerguide/waf-metrics.html
@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """AWS/WAFV2 BlockedRequests/CountedRequests equal the requests driven through a web ACL, under
    WebACL/Rule/Region; a blocking rule with CloudWatchMetricsEnabled=false publishes nothing.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/waf-metrics.html
    """
    wafv2 = ctx.client("wafv2")
    cw = ctx.client("cloudwatch")

    invoke_url, stage_arn = _rest_api_with_mock_stage(ctx)

    blocked_metric = _metric_name(ctx, "Blocked")
    counted_metric = _metric_name(ctx, "Counted")
    quiet_metric = _metric_name(ctx, "Quiet")
    acl_metric = _metric_name(ctx, "Acl")

    acl_name = ctx.unique_name("sim2real-cwwaf-")[:64]
    created = wafv2.create_web_acl(
        Name=acl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        Rules=[
            _byte_match_rule("blockme", 0, "/blocked", {"Block": {}}, blocked_metric, True),
            _byte_match_rule("countme", 1, "/counted", {"Count": {}}, counted_metric, True),
            # The twin: same action, same statement shape, metrics OFF.
            _byte_match_rule("quiet", 2, "/quiet", {"Block": {}}, quiet_metric, False),
        ],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": acl_metric,
        },
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__wafv2"}],
    )
    acl_id = created["Summary"]["Id"]
    acl_arn = created["Summary"]["ARN"]

    def _delete_acl() -> None:
        token = wafv2.get_web_acl(Name=acl_name, Scope="REGIONAL", Id=acl_id)["LockToken"]
        wafv2.delete_web_acl(Name=acl_name, Scope="REGIONAL", Id=acl_id, LockToken=token)

    # Reverse dependency order: the ACL cannot be deleted while it is associated.
    ctx.on_cleanup(_delete_acl)
    # AssociateWebACL answers WAFUnavailableEntityException for a while after the stage is created.
    _associate_with_retry(
        ctx, wafv2, acl_arn, stage_arn, timeout_s=_budget_s(ctx, _ASSOCIATION_RETRY_BUDGET_S),
        interval_s=_POLL_S,
    )
    ctx.on_cleanup(lambda: wafv2.disassociate_web_acl(ResourceArn=stage_arn))

    # ---- leg 1: enforcement is real, on a real HTTPS request ---------------------------------- #
    # Association propagates gradually: a 403 can be followed by a 200, so require a steady window.
    # Probe /quiet (metrics disabled) so probe requests never inflate an exactly-asserted Sum.
    _poll_until_steady(
        ctx,
        lambda: _get_status(f"{invoke_url}/quiet"),
        lambda s: s == 403,
        window_s=_ENFORCEMENT_STEADY_S,
        timeout_s=_budget_s(ctx, _ENFORCEMENT_BUDGET_S),
        interval_s=_POLL_S,
        description=(
            f"web ACL {acl_name} taking effect on stage {stage_arn}: GET /quiet returning 403"
        ),
    )

    # The quiet requests go first, so the positive series below cover traffic sent after them.
    for i in range(_N_QUIET_BLOCKED):
        status = _get_status(f"{invoke_url}/quiet?i={i}")
        assert status == 403, (
            f"request {i + 1} of {_N_QUIET_BLOCKED} to /quiet returned HTTP {status}, expected 403. "
            f"The quiet rule must ENFORCE identically to the blocked rule; only its telemetry is "
            f"switched off, and its metric absence below means nothing unless it really blocked"
        )
    for i in range(_N_BLOCKED):
        status = _get_status(f"{invoke_url}/blocked?i={i}")
        assert status == 403, (
            f"request {i + 1} of {_N_BLOCKED} to /blocked returned HTTP {status}, expected 403; the "
            f"BlockedRequests total asserted below is only attributable to requests WAF blocked"
        )
    for i in range(_N_COUNTED):
        status = _get_status(f"{invoke_url}/counted?i={i}")
        assert status == 200, (
            f"request {i + 1} of {_N_COUNTED} to /counted returned HTTP {status}, expected 200 — a "
            f"Count-action rule must NOT terminate the request, it must only count it"
        )

    # ---- leg 2: the terminal read, at CloudWatch ---------------------------------------------- #
    window_start = datetime.now(timezone.utc) - timedelta(minutes=20)

    def _dps(metric: str, rule: str | None) -> list[dict]:
        dims = [{"Name": "WebACL", "Value": acl_name}, {"Name": "Region", "Value": ctx.region}]
        if rule is not None:
            dims.insert(1, {"Name": "Rule", "Value": rule})
        return cw.get_metric_statistics(
            Namespace="AWS/WAFV2",
            MetricName=metric,
            Dimensions=dims,
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]

    def _sum(metric: str, rule: str | None) -> float | None:
        dps = _dps(metric, rule)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    # Datapoints land per minute, so a sum can read partial until every request is counted.
    blocked, counted = _poll_until(
        ctx,
        lambda: _pair(
            _sum("BlockedRequests", blocked_metric), _sum("CountedRequests", counted_metric)
        ),
        lambda v: v is not None and v[0] >= _N_BLOCKED and v[1] >= _N_COUNTED,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S),
        interval_s=_POLL_S,
        description=(
            f"AWS/WAFV2 BlockedRequests for Rule={blocked_metric} and CountedRequests for "
            f"Rule={counted_metric} under WebACL={acl_name} reaching at least "
            f"{_N_BLOCKED} and {_N_COUNTED}"
        ),
    )
    assert blocked == float(_N_BLOCKED), (
        f"AWS/WAFV2 BlockedRequests Sum for WebACL={acl_name} Rule={blocked_metric} settled at "
        f"{blocked!r}, expected {float(_N_BLOCKED)} — this check received exactly {_N_BLOCKED} "
        f"403s from that rule"
    )
    assert counted == float(_N_COUNTED), (
        f"AWS/WAFV2 CountedRequests Sum for WebACL={acl_name} Rule={counted_metric} settled at "
        f"{counted!r}, expected {float(_N_COUNTED)}. CountedRequests is the metric that makes a "
        f"Count-mode rule observable at all: the request was allowed through, so the metric is the "
        f"ONLY evidence the rule matched"
    )
    assert blocked != counted, (
        f"BlockedRequests and CountedRequests both settled at {blocked!r}; the check drives "
        f"{_N_BLOCKED} and {_N_COUNTED} deliberately so that one counter serving both rules is "
        f"detectable"
    )

    for metric, rule in (
        ("BlockedRequests", blocked_metric),
        ("CountedRequests", counted_metric),
    ):
        dps = _dps(metric, rule)
        assert dps, f"AWS/WAFV2 {metric} for Rule={rule} vanished on re-read: {dps!r}"
        units = {d.get("Unit") for d in dps}
        # WAF publishes these counters with the CloudWatch Unit "None", not "Count".
        assert units == {"None"}, (
            f"AWS/WAFV2 {metric} datapoints for WebACL={acl_name} Rule={rule} carry Unit(s) "
            f"{units!r}, expected exactly {{'None'}}"
        )

    sets = _dimension_sets(cw, "AWS/WAFV2", "WebACL", acl_name)
    assert any({"WebACL", "Rule", "Region"} <= set(s) for s in sets), (
        f"ListMetrics reports dimension sets {sorted(sets)!r} for the AWS/WAFV2 series naming "
        f"WebACL={acl_name}; a top-level web-ACL rule must publish a series carrying WebACL, Rule "
        f"and Region together — without the Rule dimension a customer cannot tell which of three "
        f"rules blocked their traffic"
    )

    # ---- leg 3: the metrics-disabled twin publishes nothing, held after the positives ---------- #
    _assert_stays(
        lambda: [
            _sum("BlockedRequests", quiet_metric),
            _sum("CountedRequests", quiet_metric),
        ],
        [None, None],
        hold_s=_ABSENCE_HOLD_S,
        interval_s=_POLL_S,
        description=(
            f"the rule with CloudWatchMetricsEnabled=false (MetricName={quiet_metric}) publishes no "
            f"AWS/WAFV2 datapoint although it returned {_N_QUIET_BLOCKED} 403s on this run"
        ),
    )

    # ---- positive control, after the negative ------------------------------------------------- #
    final = _sum("BlockedRequests", blocked_metric)
    assert final == float(_N_BLOCKED), (
        f"after the twin's absence window BlockedRequests for Rule={blocked_metric} read {final!r}, "
        f"expected {float(_N_BLOCKED)} — the absence above is only meaningful while the positive "
        f"series is still served"
    )


def _metric_name(ctx, label: str) -> str:
    """A WAF MetricName accepts only alphanumerics, hyphen and underscore, max 128."""
    raw = ctx.unique_name(f"sim2realCwwaf{label}")
    return "".join(c for c in raw if c.isalnum() or c in "-_")[:128]


def _byte_match_rule(
    name_label: str,
    priority: int,
    path: str,
    action: dict,
    metric_name: str,
    metrics_enabled: bool,
) -> dict:
    return {
        "Name": f"sim2real-{name_label}",
        "Priority": priority,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": path.encode("utf-8"),
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                # The UriPath WAF sees for a REST API stage includes the stage ("/prod/blocked").
                "PositionalConstraint": "ENDS_WITH",
            }
        },
        "Action": action,
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": metrics_enabled,
            "MetricName": metric_name,
        },
    }


def _rest_api_with_mock_stage(ctx) -> tuple[str, str]:
    """A REST API whose every path returns 200 from a MOCK integration, deployed to one stage.

    Returns (invoke_url, stage_arn). A MOCK integration is used so the 200s prove WAF let the
    request through rather than proving anything about a backend.
    """
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-cwwaf-api-")
    api_id = apigw.create_rest_api(
        name=name,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "cloudwatch__wafv2"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    # A greedy proxy resource so /blocked, /counted and /quiet all resolve without three definitions.
    proxy = apigw.create_resource(restApiId=api_id, parentId=root, pathPart="{proxy+}")["id"]
    for resource_id in (root, proxy):
        apigw.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
            authorizationType="NONE",
        )
        apigw.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
            type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'},
        )
        apigw.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
            statusCode="200",
            responseModels={"application/json": "Empty"},
        )
        apigw.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="ANY",
            statusCode="200",
            responseTemplates={"application/json": '{"ok": true}'},
        )

    stage = "prod"
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    invoke_url = ctx.rest_api_url(api_id, stage)
    # WAF's ResourceArn for a REST API stage carries no account id.
    stage_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage}"
    return invoke_url, stage_arn


def _associate_with_retry(
    ctx, wafv2, web_acl_arn: str, resource_arn: str, *, timeout_s: float, interval_s: float
) -> None:
    """Retry AssociateWebACL on WAFUnavailableEntityException until the deadline; re-raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            wafv2.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=resource_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFUnavailableEntityException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("AssociateWebACL past WAFUnavailableEntityException: the run budget ended first; not graded")
    raise last_exc


def _get_status(url: str) -> int:
    """The HTTP status of a GET, with an HTTPError's own code counted as the status.

    A transport failure RAISES: an unreachable endpoint is a check failure, never a 0 that some
    later assertion might read as "not blocked".
    """
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except urllib.error.URLError as exc:
        raise AssertionError(f"the API Gateway stage was unreachable at {url}: {exc}") from exc


def _pair(a, b):
    return None if a is None or b is None else (a, b)


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _poll_until_steady(ctx, probe, predicate, *, window_s, timeout_s, interval_s, description):
    """Like `_poll_until`, but the predicate must hold on every read for a continuous window."""
    deadline = time.monotonic() + timeout_s
    streak_start = None
    last = None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if predicate(last):
            if streak_start is None:
                streak_start = now
            if now - streak_start >= window_s:
                return last
        else:
            streak_start = None
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} never held for a continuous {window_s}s within {timeout_s}s; "
        f"last read {last!r}"
    )


def _assert_stays(probe, expected, *, hold_s, interval_s=20.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

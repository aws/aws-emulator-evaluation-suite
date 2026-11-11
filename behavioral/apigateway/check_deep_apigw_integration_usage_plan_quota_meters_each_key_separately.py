"""deep-apigw-integration-usage-plan-quota-meters-each-key-separately."""
from __future__ import annotations

import datetime
import http.client
import json
import socket
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigw-integration-usage-plan-quota-meters-each-key-separately"
GROUP = "usage-plans"
SERVICES = ["apigateway"]

_QUOTA = 2


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A usage plan's DAY quota of 2 is metered per API key: once key A is refused 429 "Limit Exceeded"
    (LimitExceededException), key B in the same plan is still admitted its own 2 requests before the
    same refusal, and GetUsage reports 2 for each key."""
    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, "quota-per-key")
    rid = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="q")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=rid, httpMethod="GET",
       authorizationType="NONE", apiKeyRequired=True)
    _c(ag.put_integration, restApiId=api_id, resourceId=rid, httpMethod="GET", type="MOCK",
       requestTemplates={"application/json": '{"statusCode": 200}'})
    _c(ag.put_method_response, restApiId=api_id, resourceId=rid, httpMethod="GET",
       statusCode="200")
    _c(ag.put_integration_response, restApiId=api_id, resourceId=rid, httpMethod="GET",
       statusCode="200", selectionPattern="",
       responseTemplates={"application/json": '{"route": "quota"}'})
    stage = "metered"
    _deploy_stage(ctx, api_id, stage)

    keys = {}
    for label in ("a", "b"):
        k = _c(ag.create_api_key, name=_xname(ctx, f"key{label}"), enabled=True,
               tags=dict(_TAGS))
        ctx.on_cleanup(lambda kid=k["id"]: _c(ag.delete_api_key, apiKey=kid))
        keys[label] = k

    plan_id = _c(ag.create_usage_plan, name=_xname(ctx, "plan"),
                 apiStages=[{"apiId": api_id, "stage": stage}],
                 quota={"limit": _QUOTA, "period": "DAY"},
                 throttle={"rateLimit": 200.0, "burstLimit": 200}, tags=dict(_TAGS))["id"]

    def _drop_plan():
        # A usage plan with an attached stage cannot be deleted; detach first.
        _c(ag.update_usage_plan, usagePlanId=plan_id, patchOperations=[
            {"op": "remove", "path": "/apiStages", "value": f"{api_id}:{stage}"}])
        _c(ag.delete_usage_plan, usagePlanId=plan_id)

    ctx.on_cleanup(_drop_plan)
    for label in ("a", "b"):
        kid = keys[label]["id"]
        _c(ag.create_usage_plan_key, usagePlanId=plan_id, keyId=kid, keyType="API_KEY")
        ctx.on_cleanup(lambda k=kid: _c(ag.delete_usage_plan_key, usagePlanId=plan_id, keyId=k))

    url = _rest_invoke_url(ctx, api_id, stage, "/q")

    def call(label):
        return _raw_request("GET", url, [("x-api-key", keys[label]["value"]),
                                         ("Accept", "application/json")])

    def consume(label):
        """Count ADMITTED requests until the first 429. A 403 means the key->plan
        association has not reached this edge yet (propagation is asynchronous and
        non-atomic) and consumes no quota, so it is tolerated and retried."""
        admitted, seen = [], []
        deadline = time.monotonic() + 240.0
        while time.monotonic() < deadline and len(admitted) <= _QUOTA + 4:
            try:
                status, headers, text = call(label)
            except socket.gaierror:
                # The fresh execute-api hostname has not resolved yet: nothing reached the
                # edge, so nothing was metered.
                seen.append("dns")
                time.sleep(3.0)
                continue
            seen.append(status)
            if status == 200:
                admitted.append(text)
                continue
            if status == 429:
                return admitted, (status, headers, text), seen
            assert status == 403, (
                f"key {label}: expected only 200, 429 or a propagation 403, got {status}: "
                f"{text!r}; sequence {seen!r}")
            assert json.loads(text) == {"message": "Forbidden"}, (
                f"key {label}: unexpected propagation 403 body {text!r}")
            time.sleep(3.0)
        return admitted, None, seen

    def assert_quota_rejection(label, admitted, rejection, seen):
        assert admitted, f"key {label} was never admitted; sequence {seen!r}"
        assert json.loads(admitted[0]) == {"route": "quota"}, (
            f"an admitted request must reach the MOCK integration, got {admitted[0]!r}")
        assert rejection is not None, (
            f"key {label} was admitted {len(admitted)} times and never refused; the DAY "
            f"quota of {_QUOTA} was not enforced; sequence {seen!r}")
        assert len(admitted) == _QUOTA, (
            f"key {label} must be admitted exactly its quota of {_QUOTA}, was admitted "
            f"{len(admitted)}; sequence {seen!r}")
        _s, headers, text = rejection
        assert json.loads(text) == {"message": "Limit Exceeded"}, (
            f"key {label}: expected the quota message 'Limit Exceeded', got {text!r}")
        assert headers.get("x-amzn-errortype") == "LimitExceededException", (
            f"key {label}: expected LimitExceededException, got "
            f"{headers.get('x-amzn-errortype')!r}")

    a_admitted, a_rej, a_seen = consume("a")
    assert_quota_rejection("a", a_admitted, a_rej, a_seen)

    # Positive control for "per key": B, in the SAME plan, is untouched by A's exhaustion.
    b_admitted, b_rej, b_seen = consume("b")
    assert_quota_rejection("b", b_admitted, b_rej, b_seen)

    # A stays exhausted (a 403 from a lagging edge is still a refusal; a 200 is a reopen).
    after = [call("a")[0] for _ in range(2)]
    assert 200 not in after, f"key a was admitted again after exhausting its quota: {after!r}"

    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    for label in ("a", "b"):
        kid = keys[label]["id"]
        used = None
        deadline = time.monotonic() + 120.0
        while time.monotonic() < deadline:
            items = _c(ag.get_usage, usagePlanId=plan_id, keyId=kid, startDate=today,
                       endDate=today).get("items", {}).get(kid, [])
            if items and items[0] and items[0][0] == _QUOTA:
                used = items[0][0]
                break
            used = items[0][0] if items and items[0] else None
            time.sleep(5.0)
        assert used == _QUOTA, (
            f"GetUsage for key {label} reported {used!r} used on {today}; the edge admitted "
            f"exactly {_QUOTA} for that key")


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx, kind):
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _c(fn, **kw):
    """Call an apigateway control-plane op, retrying only its per-account mutation throttle."""
    for attempt in range(10):
        try:
            return fn(**kw)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or attempt == 9:
                raise
            time.sleep(min(4.0, 0.3 * (2 ** attempt)))
    raise RuntimeError("unreachable")


def _poll(probe, predicate, description, timeout_s=150.0, interval_s=3.0):
    """Poll probe() to a condition (stage propagation), tolerating connection errors while
    execute-api DNS settles."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = probe()
        except OSError as exc:
            last = ("connection error", {}, repr(exc))
        else:
            if predicate(last):
                return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: condition not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _raw_request(method, url, header_pairs, body=None):
    """HTTP via http.client; returns (status, lower-cased headers, text). A 4xx/5xx is a
    result, not an exception."""
    u = urllib.parse.urlsplit(url)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.netloc, timeout=25)
    try:
        conn.putrequest(method, u.path + (f"?{u.query}" if u.query else ""),
                        skip_accept_encoding=True)
        for k, v in header_pairs:
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        resp = conn.getresponse()
        return (resp.status, {k.lower(): v for k, v in resp.getheaders()},
                resp.read().decode("utf-8", "replace"))
    finally:
        conn.close()


def _rest_invoke_url(ctx, api_id, stage, path):
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _create_rest_api(ctx, kind, **extra):
    ag = ctx.client("apigateway")
    api_id = _c(ag.create_rest_api, name=_xname(ctx, kind), description=f"sim2real {CHECK}",
                endpointConfiguration={"types": ["REGIONAL"]}, tags=dict(_TAGS), **extra)["id"]
    ctx.on_cleanup(lambda: _c(ag.delete_rest_api, restApiId=api_id))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage, variables=None):
    ag = ctx.client("apigateway")
    dep_id = _c(ag.create_deployment, restApiId=api_id)["id"]
    kw = {"restApiId": api_id, "stageName": stage, "deploymentId": dep_id}
    if variables:
        kw["variables"] = variables
    _c(ag.create_stage, **kw)
    ctx.on_cleanup(lambda: _c(ag.delete_stage, restApiId=api_id, stageName=stage))
    return dep_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

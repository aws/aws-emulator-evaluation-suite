"""apigw-usage-plan-daily-quota-exhaustion-rejects-over-http."""
from __future__ import annotations

import datetime
import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-usage-plan-daily-quota-exhaustion-rejects-over-http"
GROUP = 'usage-plans'
SERVICES = ['apigateway']

_QUOTA = 2


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    This guards the CONTROL plane (apigateway's per-account mutation limit), a different
    limiter from the usage-plan quota under test here."""
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _create_api(ctx, ag, scenario):
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    The name, the description AND the tag all carry the sim2real marker."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": scenario},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id


def _http(method, url, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a path on a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Once a usage plan's DAY quota of two is consumed, the stage answers 429 "Limit Exceeded" with
    LimitExceededException and admits nothing more; a key outside the plan gets 403, and GetUsage
    reports exactly the admitted count."""
    ag = ctx.client("apigateway")

    api_id = _create_api(ctx, ag, "usage-plan-daily-quota")
    q_id = _child(ctx, ag, api_id, "q")
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=q_id, httpMethod="GET",
        authorizationType="NONE", apiKeyRequired=True,
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=q_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode":200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=q_id, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=q_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"route":"quota"}'},
    ))

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="test", deploymentId=deployment_id,
        tags={"sim2real": "usage-plan-daily-quota"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName="test")))

    # Quota counters are per key per UTC day, so fresh keys keep a re-run from starting exhausted.
    key_a = _retry_throttled(lambda: ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-apigw-keya-"),
        description="sim2real usage-plan-daily-quota A", enabled=True,
        tags={"sim2real": "usage-plan-daily-quota"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_api_key(apiKey=key_a["id"])))
    key_b = _retry_throttled(lambda: ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-apigw-keyb-"),
        description="sim2real usage-plan-daily-quota B", enabled=True,
        tags={"sim2real": "usage-plan-daily-quota"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_api_key(apiKey=key_b["id"])))

    plan = _retry_throttled(lambda: ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-apigw-plan-"),
        description="sim2real usage-plan-daily-quota",
        apiStages=[{"apiId": api_id, "stage": "test"}],
        quota={"limit": _QUOTA, "period": "DAY"},
        # Two orders of magnitude above the request rate below, so a rate/burst 429 can
        # never be mistaken for the quota 429 this check is about.
        throttle={"rateLimit": 200.0, "burstLimit": 200},
        tags={"sim2real": "usage-plan-daily-quota"},
    ))
    plan_id = plan["id"]

    def _drop_plan():
        # A usage plan cannot be deleted while it still has apiStages attached. Both calls are
        # throttle-retried because teardown issues several mutations back to back.
        _retry_throttled(lambda: ag.update_usage_plan(
            usagePlanId=plan_id, patchOperations=[
                {"op": "remove", "path": "/apiStages", "value": f"{api_id}:test"}]))
        _retry_throttled(lambda: ag.delete_usage_plan(usagePlanId=plan_id))

    ctx.on_cleanup(_drop_plan)

    _retry_throttled(lambda: ag.create_usage_plan_key(
        usagePlanId=plan_id, keyId=key_a["id"], keyType="API_KEY"))
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_usage_plan_key(
        usagePlanId=plan_id, keyId=key_a["id"])))

    url = _apigw_url(ctx, api_id, "test", "/q")
    hdr_a = {"x-api-key": key_a["value"]}

    # The key-to-plan association reaches the edge asynchronously and non-atomically: a 200 can
    # be followed by a 403 that consumes no quota. So admitted requests are counted.
    admitted_bodies: list[str] = []
    observed: list[int] = []
    rejection = None
    # The cap counts ADMITTED requests, not attempts, which propagation 403s would use up.
    max_admitted = _QUOTA + 6
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline and len(admitted_bodies) < max_admitted:
        status, resp_headers, text = _http("GET", url, headers=hdr_a)
        observed.append(status)
        if status == 200:
            admitted_bodies.append(text)
            continue
        if status == 429:
            rejection = (status, resp_headers, text)
            break
        assert status == 403, (
            f"expected only 200 (admitted), 429 (quota) or 403 (association not yet "
            f"effective) while consuming the quota, got {status!r}: {text!r}; sequence so "
            f"far {observed!r}"
        )
        time.sleep(3.0)

    assert admitted_bodies, (
        f"the api key never became effective on the deployed stage within 180s; status "
        f"sequence {observed!r} — without an admitted request there is no quota to exhaust"
    )
    assert json.loads(admitted_bodies[0]) == {"route": "quota"}, (
        f"an admitted in-quota request must reach the MOCK integration, got "
        f"{admitted_bodies[0]!r}"
    )
    assert rejection is not None, (
        f"the edge admitted {len(admitted_bodies)} requests and never enforced the DAY "
        f"quota of {_QUOTA}; status sequence {observed!r}"
    )
    assert len(admitted_bodies) == _QUOTA, (
        f"expected the edge to admit exactly the configured DAY quota of {_QUOTA} requests "
        f"before rejecting, but it admitted {len(admitted_bodies)}; status sequence "
        f"{observed!r}"
    )
    assert json.loads(rejection[2])["message"] == "Limit Exceeded", (
        f"expected the QUOTA message 'Limit Exceeded' rather than the throttle's 'Too Many "
        f"Requests', got {rejection[2]!r}"
    )
    assert rejection[1].get("x-amzn-errortype") == "LimitExceededException", (
        f"expected x-amzn-ErrorType: LimitExceededException on the quota rejection, got "
        f"{rejection[1].get('x-amzn-errortype')!r} (all headers {rejection[1]!r})"
    )
    assert "route" not in json.loads(rejection[2]), (
        f"the MOCK integration ran on a quota-rejected request — its body leaked into "
        f"{rejection[2]!r}"
    )

    # The quota does not reopen. Only non-admission is asserted: the non-atomic association can
    # also answer 403 (e.g. [403, 403, 403]), which is still a refusal.
    after = [_http("GET", url, headers=hdr_a)[0] for _ in range(3)]
    assert 200 not in after, (
        f"once the DAY quota of {_QUOTA} is consumed no further request may be admitted, "
        f"but one of the next three was: {after!r}"
    )

    status_b, _hb, body_b = _http("GET", url, headers={"x-api-key": key_b["value"]})
    assert status_b == 403, (
        f"expected 403 for an enabled key that is not associated with the plan, got "
        f"{status_b!r}: {body_b!r}"
    )
    assert json.loads(body_b) == {"message": "Forbidden"}, (
        f'expected the opaque body {{"message": "Forbidden"}} for a key outside the plan, got {body_b!r}'
    )

    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    used = None
    usage_deadline = time.monotonic() + 120.0
    while time.monotonic() < usage_deadline:
        usage = ag.get_usage(usagePlanId=plan_id, keyId=key_a["id"],
                             startDate=today, endDate=today)
        days = usage.get("items", {}).get(key_a["id"], [])
        if days and days[0]:
            used = days[0][0]
            break
        time.sleep(5.0)
    assert used == _QUOTA, (
        f"GetUsage reported {used!r} consumed for key {key_a['id']!r} on {today}, but the "
        f"edge admitted exactly {_QUOTA} requests and rejected the next one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

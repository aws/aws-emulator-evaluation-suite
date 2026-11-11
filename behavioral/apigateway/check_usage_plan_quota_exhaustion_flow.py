"""usage-plan-quota-exhaustion-flow."""
from __future__ import annotations

import datetime as dt
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "usage-plan-quota-exhaustion-flow"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Real requests at an api-key-gated stage consume a usage plan's quota until GetUsage shows
    remaining 0 and further requests get the quota 429 ("Limit Exceeded", not the rate throttle's
    "Too Many Requests"); an UpdateUsage extension then lets a real request through again."""
    apigw = ctx.client("apigateway")

    rest_api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-quota-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET",
        authorizationType="NONE", apiKeyRequired=True,
    )
    apigw.put_integration(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200", selectionPattern="",
    )
    apigw.create_deployment(restApiId=rest_api_id, stageName="test")

    quota_limit = 3
    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-quota-plan-"),
        apiStages=[{"apiId": rest_api_id, "stage": "test"}],
        quota={"limit": quota_limit, "period": "DAY"},
        throttle={"rateLimit": 500.0, "burstLimit": 500},
    )["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan(apigw, plan_id, f"{rest_api_id}:test"))

    key_created = apigw.create_api_key(name=ctx.unique_name("sim2real-quota-key-"), enabled=True)
    key_id = key_created["id"]
    key_value = key_created["value"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    invoke_url = f"{ctx.rest_api_url(rest_api_id, 'test')}/"

    def _invoke_detailed():
        req = urllib.request.Request(invoke_url, headers={"x-api-key": key_value})
        try:
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context(ctx.http_verify)) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, body

    def _invoke():
        return _invoke_detailed()[0]

    # New API keys/usage-plan associations take a little time to propagate; poll until
    # the key is actually recognized (200) rather than rejected as unknown (403).
    deadline = time.monotonic() + 90
    status = None
    while time.monotonic() < deadline:
        status = _invoke()
        if status == 200:
            break
        time.sleep(3)
    assert status == 200, f"expected the api-key-gated request to eventually succeed (200), last status={status}"

    # Consume the rest of the quota with real requests (1 already used above). Even on a
    # REGIONAL endpoint, propagation can be momentarily inconsistent, so retry each call.
    def _invoke_with_retry(max_wait_s: float = 30.0) -> int:
        deadline = time.monotonic() + max_wait_s
        last = None
        while time.monotonic() < deadline:
            last = _invoke()
            if last == 200:
                return last
            time.sleep(2)
        return last

    for _ in range(quota_limit - 1):
        status = _invoke_with_retry()
        assert status == 200, f"expected requests within quota to succeed (200), got {status}"


    # With the quota exhausted, GetUsage must show used == limit and remaining == 0, and a further
    # request must get a 429 (after a propagation delay).
    deadline = time.monotonic() + 60
    used = remaining = None
    while time.monotonic() < deadline:
        usage = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
        used, remaining = usage["items"][key_id][-1]
        if remaining == 0:
            break
        time.sleep(3)
    assert used == quota_limit, f"expected GetUsage used=={quota_limit} once quota is exhausted, got {used}"
    assert remaining == 0, f"expected GetUsage remaining==0 once quota is exhausted, got {remaining}"

    deadline = time.monotonic() + 30
    throttled_status, throttled_headers, throttled_body = None, {}, ""
    while time.monotonic() < deadline:
        throttled_status, throttled_headers, throttled_body = _invoke_detailed()
        if throttled_status == 429:
            break
        time.sleep(2)
    assert throttled_status == 429, f"expected a request beyond the exhausted quota to be throttled (429), got {throttled_status}"
    # The quota rejection is a specific contract, distinct from the rate/burst throttle's
    # "Too Many Requests" (rateLimit/burstLimit are set two orders of magnitude above this
    # check's request volume, but the code and message are what actually separate them).
    assert throttled_headers.get("x-amzn-errortype") == "LimitExceededException", (
        f"expected the quota rejection's x-amzn-ErrorType to be LimitExceededException, "
        f"got {throttled_headers.get('x-amzn-errortype')!r} (headers {throttled_headers!r})"
    )
    assert json.loads(throttled_body).get("message") == "Limit Exceeded", (
        f"expected the QUOTA message 'Limit Exceeded' rather than the throttle's 'Too Many "
        f"Requests', got {throttled_body!r}"
    )

    # UpdateUsage grants a temporary extension to `remaining` — GetUsage reflects it.
    apigw.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "5"}],
    )
    usage = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    _used, remaining = usage["items"][key_id][-1]
    assert remaining == 5, f"expected UpdateUsage's extension reflected by GetUsage, got remaining={remaining}"

    # The extension must also unblock a real request through the deployed stage, not only read back
    # from GetUsage.
    unblocked_status = _invoke_with_retry()
    assert unblocked_status == 200, (
        f"expected UpdateUsage's extension to unblock a real request (200), got {unblocked_status}"
    )


def _delete_usage_plan(apigw, plan_id: str, api_stage: str) -> None:
    """DeleteUsagePlan refuses a plan that still has API stages; detach the stage first."""
    apigw.update_usage_plan(
        usagePlanId=plan_id, patchOperations=[{"op": "remove", "path": "/apiStages", "value": api_stage}],
    )
    apigw.delete_usage_plan(usagePlanId=plan_id)


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

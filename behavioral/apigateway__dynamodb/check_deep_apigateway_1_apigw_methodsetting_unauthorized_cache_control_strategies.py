"""deep-apigateway-1-apigw-methodsetting-unauthorized-cache-control-strategies."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deep-apigateway-1-apigw-methodsetting-unauthorized-cache-control-strategies"
GROUP = "method-settings-caching"
SERVICES = ["apigateway", "dynamodb"]

# Whole-check budget. A fresh 0.5 GB stage cache cluster takes ~310 s to reach AVAILABLE, and
# each MethodSetting flip below takes 20-60 s to settle across the gateway fleet (responses
# flap between old and new behaviour meanwhile).
_BUDGET_S = 1500
_CLUSTER_WAIT_S = 720
_SETTLE_TIMEOUT_S = 180
# Enabling caching can settle in ~20 s or take over 180 s (hits interleaved with backend
# invocations), so the first-hit wait gets its own larger budget.
_WARM_TIMEOUT_S = 420

_WARNING = "199 Cache-control headers were ignored because the caller was unauthorized."
_P = "/~1count/GET/caching/"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Unauthorized `Cache-Control: max-age=0` follows unauthorizedCacheControlHeaderStrategy (403,
    200 + Warning, or a silent cache hit); only requireAuthorizationForCacheControl=false lets it
    invalidate, proven by a DynamoDB counter the backend increments on every invocation.
    """
    apigw = ctx.client("apigateway")
    ddb = ctx.client("dynamodb")
    start = time.monotonic()

    table = _create_counter_table(ctx)
    role_arn = _create_integration_role(ctx, table)
    api_id = _create_counter_api(ctx, table, role_arn)
    stage = "cc"
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id,
                       cacheClusterEnabled=True, cacheClusterSize="0.5")
    # Registered before the multi-minute provisioning wait: a cache cluster bills hourly.
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage))
    url = f"{ctx.rest_api_url(api_id, stage)}/count"

    def counter() -> int:
        item = ddb.get_item(TableName=table, Key={"pk": {"S": "counter"}},
                            ConsistentRead=True).get("Item")
        return int(item["n"]["N"]) if item else 0

    # The integration role's IAM propagation overlaps the cluster provisioning; the first 200
    # proves the backend is wired before any caching is in play.
    status, _, body = _wait_for_status(url, 200, timeout_s=180)
    assert status == 200, f"backend never answered 200 before caching: {status} {body!r}"
    first = json.loads(body)
    assert int(first["n"]) == counter() >= 1, (
        f"uncached call body {first!r} disagrees with the out-of-band counter {counter()!r}"
    )

    cluster = _wait_for_cluster(apigw, api_id, stage, timeout_s=min(_CLUSTER_WAIT_S, _left(start) - 600))
    assert cluster == "AVAILABLE", f"cache cluster never became AVAILABLE: {cluster!r}"

    apigw.update_stage(restApiId=api_id, stageName=stage, patchOperations=[
        {"op": "replace", "path": _P + "enabled", "value": "true"},
        {"op": "replace", "path": _P + "ttlInSeconds", "value": "300"},
    ])
    ms = apigw.get_stage(restApiId=api_id, stageName=stage)["methodSettings"]["~1count/GET"]
    assert ms.get("requireAuthorizationForCacheControl") is True, (
        f"requireAuthorizationForCacheControl default should be true, got {ms!r}"
    )
    assert ms.get("unauthorizedCacheControlHeaderStrategy") == "SUCCEED_WITH_RESPONSE_HEADER", (
        f"unauthorizedCacheControlHeaderStrategy default should be SUCCEED_WITH_RESPONSE_HEADER, got {ms!r}"
    )

    # Warm: a long run of consecutive plain hits. Right after caching is enabled, some requests
    # are served by nodes that invoke the backend without caching, so the
    # counter can run AHEAD of the cached value; only "no invocation across these calls" is an
    # invariant, never "cached n == counter".
    cached_n = _wait_for_plain_hit(url, counter, timeout_s=_WARM_TIMEOUT_S, k=8)

    # Every observation below is (counter before, unauthorized Cache-Control GET, counter after,
    # plain GET, counter after) -- so each one proves, by itself, whether either call ran the
    # backend.
    def observe() -> dict:
        c0 = counter()
        st, hdrs, b = _cc_call(url)
        c1 = counter()
        pst, _, pb = _get(url)
        c2 = counter()
        return {"st": st, "hdrs": hdrs, "body": b, "c0": c0, "c1": c1,
                "pst": pst, "pn": _n(pb) if pst == 200 else None, "c2": c2}

    def held(o: dict) -> bool:
        # Neither call invoked the backend, and the plain GET (positive control) hit the cache.
        return o["c0"] == o["c1"] == o["c2"] and o["pst"] == 200 and o["pn"] == cached_n

    # ---- FAIL_WITH_403 -------------------------------------------------------------------
    _set_strategy(apigw, api_id, stage, require="true", strategy="FAIL_WITH_403")
    obs = _settle(observe, lambda o: o["st"] == 403 and held(o), k=3,
                  timeout_s=_SETTLE_TIMEOUT_S, what="FAIL_WITH_403 -> 403")
    for o in obs:
        assert o["st"] == 403, f"FAIL_WITH_403: unauthorized Cache-Control got {o['st']} {o['body']!r}"
        assert o["hdrs"].get("x-amzn-errortype") == "MissingAuthenticationTokenException", (
            f"FAIL_WITH_403: x-amzn-ErrorType was {o['hdrs'].get('x-amzn-errortype')!r}"
        )
        assert "warning" not in o["hdrs"], f"FAIL_WITH_403: a 403 carried a Warning header {o['hdrs']!r}"
        assert o["c0"] == o["c1"], (
            f"FAIL_WITH_403: a refused Cache-Control request invoked the backend "
            f"(counter {o['c0']!r} -> {o['c1']!r})"
        )
        assert o["pst"] == 200 and o["pn"] == cached_n and o["c1"] == o["c2"], (
            f"FAIL_WITH_403 positive control: plain GET {o['pst']} n={o['pn']!r} counter "
            f"{o['c1']!r}->{o['c2']!r}, expected a 200 cache hit on n={cached_n!r}"
        )

    # ---- SUCCEED_WITH_RESPONSE_HEADER ----------------------------------------------------
    _set_strategy(apigw, api_id, stage, require="true", strategy="SUCCEED_WITH_RESPONSE_HEADER")
    obs = _settle(observe, lambda o: (o["st"] == 200 and o["hdrs"].get("warning") == _WARNING
                                      and _n(o["body"]) == cached_n and held(o)),
                  k=3, timeout_s=_SETTLE_TIMEOUT_S, what="SUCCEED_WITH_RESPONSE_HEADER -> 200+Warning")
    for o in obs:
        assert o["st"] == 200 and _n(o["body"]) == cached_n, (
            f"SUCCEED_WITH_RESPONSE_HEADER: {o['st']} {o['body']!r} is not the cached n={cached_n!r} "
            f"-- the unauthorized header must be ignored, not honoured"
        )
        assert o["hdrs"].get("warning") == _WARNING, f"Warning header was {o['hdrs'].get('warning')!r}"
        assert o["c0"] == o["c1"] == o["c2"], (
            f"SUCCEED_WITH_RESPONSE_HEADER: the ignored header invoked the backend "
            f"(counter {o['c0']!r}->{o['c1']!r}->{o['c2']!r})"
        )

    # ---- SUCCEED_WITHOUT_RESPONSE_HEADER -------------------------------------------------
    _set_strategy(apigw, api_id, stage, require="true", strategy="SUCCEED_WITHOUT_RESPONSE_HEADER")
    obs = _settle(observe, lambda o: (o["st"] == 200 and "warning" not in o["hdrs"]
                                      and _n(o["body"]) == cached_n and held(o)),
                  k=4, timeout_s=_SETTLE_TIMEOUT_S, what="SUCCEED_WITHOUT_RESPONSE_HEADER -> 200, no Warning")
    for o in obs:
        assert o["st"] == 200 and _n(o["body"]) == cached_n, (
            f"SUCCEED_WITHOUT_RESPONSE_HEADER: {o['st']} {o['body']!r} is not the cached n={cached_n!r}"
        )
        assert "warning" not in o["hdrs"], (
            f"SUCCEED_WITHOUT_RESPONSE_HEADER sent Warning {o['hdrs'].get('warning')!r}"
        )
        assert o["c0"] == o["c1"] == o["c2"], (
            f"SUCCEED_WITHOUT_RESPONSE_HEADER: the ignored header invoked the backend "
            f"(counter {o['c0']!r}->{o['c1']!r}->{o['c2']!r})"
        )

    # ---- requireAuthorizationForCacheControl=false: the header now invalidates ---------------
    apigw.update_stage(restApiId=api_id, stageName=stage, patchOperations=[
        {"op": "replace", "path": _P + "requireAuthorizationForCacheControl", "value": "false"},
    ])

    def invalidated(o: dict) -> bool:
        # The Cache-Control GET ran the backend exactly once and returned its new count, and the
        # plain GET right after was a hit on THAT refreshed entry -- which a node merely not
        # caching would not produce.
        return (o["st"] == 200 and o["c1"] == o["c0"] + 1 and _n(o["body"]) == o["c1"]
                and o["pst"] == 200 and o["pn"] == o["c1"] and o["c2"] == o["c1"])

    obs = _settle(observe, invalidated, k=3, timeout_s=_SETTLE_TIMEOUT_S,
                  what="requireAuthorizationForCacheControl=false -> cache invalidated and refreshed")
    seen_n = []
    for o in obs:
        n = _n(o["body"])
        assert o["c1"] == o["c0"] + 1 and n == o["c1"], (
            f"invalidating request: counter {o['c0']!r}->{o['c1']!r}, body n={n!r}"
        )
        assert "warning" not in o["hdrs"], f"a permitted invalidation carried Warning {o['hdrs']!r}"
        assert o["pn"] == n and o["c2"] == o["c1"], (
            f"plain GET after invalidation returned n={o['pn']!r} (counter {o['c2']!r}); expected "
            f"a hit on the refreshed n={n!r}"
        )
        seen_n.append(n)
    assert seen_n == sorted(set(seen_n)) and seen_n[0] > cached_n, (
        f"bodies did not change per call after the cache was invalidated: {seen_n!r} (cached {cached_n!r})"
    )


def _left(start: float) -> float:
    return _BUDGET_S - (time.monotonic() - start)


def _get(url: str, headers: dict | None = None, timeout_s: float = 15.0) -> tuple[int, dict, str]:
    """One GET; returns (status, lower-cased headers, body) for 2xx and HTTP errors alike."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read().decode()


def _cc_call(url: str) -> tuple[int, dict, str]:
    return _get(url, {"Cache-Control": "max-age=0"})


def _wait_for_status(url: str, want: int, timeout_s: float) -> tuple[int, dict, str]:
    deadline = time.monotonic() + timeout_s
    last: tuple = (None, {}, "")
    while time.monotonic() < deadline:
        try:
            last = _get(url)
        except (urllib.error.URLError, TimeoutError) as exc:  # DNS / connect propagation
            last = (None, {}, repr(exc))
        if last[0] == want:
            return last
        time.sleep(3)
    return last


def _wait_for_cluster(apigw, api_id: str, stage: str, timeout_s: float) -> str | None:
    deadline = time.monotonic() + max(60.0, timeout_s)
    status = None
    while time.monotonic() < deadline:
        status = apigw.get_stage(restApiId=api_id, stageName=stage).get("cacheClusterStatus")
        if status == "AVAILABLE":
            return status
        time.sleep(2)
    return status


def _n(body: str) -> int:
    """The backend counter value the response carries -- the part of the body the cache holds
    ($context.requestId in the same template is re-rendered per request, even on a hit)."""
    return int(json.loads(body)["n"])


def _wait_for_plain_hit(url: str, counter, timeout_s: float, k: int = 3) -> int:
    """Poll plain GETs until `k` consecutive ones carry the same counter value without the
    counter moving -- a settled cache hit after enabling per-method caching."""
    deadline = time.monotonic() + timeout_s
    run: list = []
    while time.monotonic() < deadline:
        st, _, b = _get(url)
        c = counter()
        n = _n(b) if st == 200 else None
        if n is not None and run and run[-1] == (n, c):
            run.append((n, c))
            if len(run) >= k:
                return n
        else:
            run = [(n, c)] if n is not None else []
        time.sleep(2)
    raise AssertionError(f"never observed {k} consecutive cache hits within {timeout_s}s; last {run[-1:]!r}")


def _set_strategy(apigw, api_id: str, stage: str, require: str, strategy: str) -> None:
    apigw.update_stage(restApiId=api_id, stageName=stage, patchOperations=[
        {"op": "replace", "path": _P + "requireAuthorizationForCacheControl", "value": require},
        {"op": "replace", "path": _P + "unauthorizedCacheControlHeaderStrategy", "value": strategy},
    ])
    got = apigw.get_stage(restApiId=api_id, stageName=stage)["methodSettings"]["~1count/GET"]
    assert got.get("unauthorizedCacheControlHeaderStrategy") == strategy, (
        f"GetStage did not echo strategy {strategy!r}: {got!r}"
    )


def _settle(probe, pred, k: int, timeout_s: float, what: str) -> list:
    """Re-probe until `k` CONSECUTIVE observations satisfy `pred`; return those k.

    A MethodSetting change reaches the gateway fleet gradually, so for 20-60 s responses flap
    between the old and new behaviour. A run of k consecutive new-behaviour responses is the
    observable condition that the setting has landed; the caller then asserts its invariants on
    exactly those responses.
    """
    deadline = time.monotonic() + timeout_s
    run: list = []
    history: list = []
    while time.monotonic() < deadline:
        o = probe()
        history.append({k: v for k, v in o.items() if k != "hdrs"} | {"warning": o["hdrs"].get("warning")})
        if pred(o):
            run.append(o)
            if len(run) >= k:
                return run
        else:
            run = []
        time.sleep(2)
    raise AssertionError(f"{what}: never saw {k} consecutive matching responses in {timeout_s}s; "
                         f"last observations {history[-6:]!r}")


def _create_counter_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-xsvc-msett-cc-")
    ddb.create_table(TableName=table, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    # Registered before the wait: DeleteTable on a CREATING table fails, so the cleanup itself
    # waits for ACTIVE first.
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return table


def _delete_table(ddb, table: str) -> None:
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    ddb.delete_table(TableName=table)


def _create_integration_role(ctx, table: str) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-msett-cc-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="counter", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:UpdateItem",
                       "Resource": f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table}"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="counter"))
    return arn


def _create_counter_api(ctx, table: str, role_arn: str) -> str:
    """GET /count -> DynamoDB UpdateItem (ADD n 1, ReturnValues UPDATED_NEW) -> {"n", "rid"}."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-xsvc-msett-cc-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    res = apigw.create_resource(restApiId=api_id, parentId=root, pathPart="count")["id"]
    apigw.put_method(restApiId=api_id, resourceId=res, httpMethod="GET", authorizationType="NONE")
    template = json.dumps({
        "TableName": table, "Key": {"pk": {"S": "counter"}},
        "UpdateExpression": "ADD n :one",
        "ExpressionAttributeValues": {":one": {"N": "1"}},
        "ReturnValues": "UPDATED_NEW"})
    apigw.put_integration(restApiId=api_id, resourceId=res, httpMethod="GET", type="AWS",
                          integrationHttpMethod="POST",
                          uri=f"arn:aws:apigateway:{ctx.region}:dynamodb:action/UpdateItem",
                          credentials=role_arn, passthroughBehavior="NEVER",
                          requestTemplates={"application/json": template})
    apigw.put_method_response(restApiId=api_id, resourceId=res, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=res, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json":
                           '{"n": "$input.path(\'$.Attributes.n.N\')", "rid": "$context.requestId"}'})
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

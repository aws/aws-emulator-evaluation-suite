"""deep-apigateway-1-apigw-methodsetting-cache-ttl-expiry-and-flush-eviction."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deep-apigateway-1-apigw-methodsetting-cache-ttl-expiry-and-flush-eviction"
GROUP = "method-settings-caching"
SERVICES = ["apigateway", "dynamodb"]

# A fresh 0.5 GB cache cluster takes ~310 s to become AVAILABLE, then ~1-2 minutes of TTL
# observation and a flush.
_BUDGET_S = 1500
_CLUSTER_WAIT_S = 720
_SETTLE_TIMEOUT_S = 180
# Enabling caching can settle in ~20 s or take over 180 s (hits
# interleaved with backend invocations), so the first-hit wait gets its own larger budget.
_WARM_TIMEOUT_S = 420

_SHORT_TTL = 10   # seconds -- /short
_LONG_TTL = 300   # seconds -- /long, never allowed to elapse inside this check
_LIFETIMES = 3    # consecutive /short entry lifetimes measured


# timing:real-time — ttl: 10 s https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A method's cacheTtlInSeconds bounds how long the stage cache serves an entry (per method,
    not stage-wide), and FlushStageCache evicts an entry before its TTL elapses; invocations are
    counted out of band via a DynamoDB counter the integration increments."""
    apigw = ctx.client("apigateway")
    ddb = ctx.client("dynamodb")
    start = time.monotonic()

    table = _create_counter_table(ctx)
    role_arn = _create_integration_role(ctx, table)
    api_id = _create_counter_api(ctx, table, role_arn, paths=("short", "long"))
    stage = "ttl"
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    apigw.create_stage(restApiId=api_id, stageName=stage, deploymentId=deployment_id,
                       cacheClusterEnabled=True, cacheClusterSize="0.5")
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage))
    base = ctx.rest_api_url(api_id, stage)
    short_url, long_url = f"{base}/short", f"{base}/long"

    def counter(key: str) -> int:
        item = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
        return int(item["n"]["N"]) if item else 0

    for url in (short_url, long_url):
        st, _, b = _wait_for_status(url, 200, timeout_s=180)
        assert st == 200, f"backend {url} never answered 200 before caching: {st} {b!r}"

    cluster = _wait_for_cluster(apigw, api_id, stage, timeout_s=min(_CLUSTER_WAIT_S, _left(start) - 600))
    assert cluster == "AVAILABLE", f"cache cluster never became AVAILABLE: {cluster!r}"

    apigw.update_stage(restApiId=api_id, stageName=stage, patchOperations=[
        {"op": "replace", "path": "/~1short/GET/caching/enabled", "value": "true"},
        {"op": "replace", "path": "/~1short/GET/caching/ttlInSeconds", "value": str(_SHORT_TTL)},
        {"op": "replace", "path": "/~1long/GET/caching/enabled", "value": "true"},
        {"op": "replace", "path": "/~1long/GET/caching/ttlInSeconds", "value": str(_LONG_TTL)},
    ])
    ms = apigw.get_stage(restApiId=api_id, stageName=stage)["methodSettings"]
    assert ms["~1short/GET"]["cacheTtlInSeconds"] == _SHORT_TTL, f"GetStage methodSettings {ms!r}"
    assert ms["~1long/GET"]["cacheTtlInSeconds"] == _LONG_TTL, f"GetStage methodSettings {ms!r}"

    # Right after caching is enabled, AWS can serve some requests from nodes that invoke the
    # backend WITHOUT caching, so a counter may run ahead of its cached value; the invariant is
    # "no invocation across these calls", never "cached n == counter".
    long_n, long_created = _wait_for_hit(long_url, lambda: counter("long"), _WARM_TIMEOUT_S, k=8)
    short_n, _ = _wait_for_hit(short_url, lambda: counter("short"), _SETTLE_TIMEOUT_S, k=5)
    long_c0 = counter("long")

    # ---- TTL: measure consecutive /short entry lifetimes, interleaving /long hits -------------
    misses: list[tuple[float, int]] = []   # (monotonic time, n) of each /short backend invocation
    hits_per_entry: dict[int, int] = {}
    entry_n, last_c = short_n, counter("short")
    long_checks = 0
    deadline = time.monotonic() + (_LIFETIMES + 2) * (_SHORT_TTL + 20)
    while len(misses) < _LIFETIMES + 1 and time.monotonic() < deadline:
        t = time.monotonic()
        st, hdrs, b = _get(short_url)
        assert st == 200, f"/short returned {st} {b!r}"
        n = _n(b)
        c = counter("short")
        if c == last_c:
            assert n == entry_n, (
                f"/short served n={n!r} without invoking the backend, but the entry in force is "
                f"n={entry_n!r}"
            )
            # The cache holds the INTEGRATION response; the response mapping template is
            # re-evaluated per request, so $context.requestId is this request's even on a hit.
            assert json.loads(b)["rid"] == hdrs.get("x-amzn-requestid"), (
                f"cache hit body rid {json.loads(b)['rid']!r} != this response's request id "
                f"{hdrs.get('x-amzn-requestid')!r}"
            )
            hits_per_entry[n] = hits_per_entry.get(n, 0) + 1
        else:
            assert c == last_c + 1 and n == c, (
                f"/short miss should invoke the backend exactly once and return its count: "
                f"counter {last_c!r}->{c!r}, body n={n!r}"
            )
            misses.append((t, n))
            entry_n, last_c = n, c
        st, _, lb = _get(long_url)
        assert st == 200 and _n(lb) == long_n, (
            f"/long (TTL {_LONG_TTL}s) changed inside its window while /short expired: "
            f"{st} {lb!r}, cached n={long_n!r}"
        )
        long_checks += 1
        time.sleep(1)
    assert len(misses) == _LIFETIMES + 1, (
        f"/short (TTL {_SHORT_TTL}s) produced only {len(misses)} backend invocations in "
        f"{(_LIFETIMES + 2) * (_SHORT_TTL + 20)}s -- entries are not expiring; misses={misses!r}"
    )
    lifetimes = [round(misses[i + 1][0] - misses[i][0], 1) for i in range(_LIFETIMES)]
    for i, life in enumerate(lifetimes):
        n = misses[i][1]
        assert hits_per_entry.get(n, 0) >= 3, (
            f"/short entry n={n} was served as a hit only {hits_per_entry.get(n, 0)} times before "
            f"expiring -- not cached for its TTL; lifetimes={lifetimes!r}"
        )
        assert _SHORT_TTL - 3 <= life <= _SHORT_TTL + 12, (
            f"/short entry lifetime {life}s is not ~{_SHORT_TTL}s TTL; lifetimes={lifetimes!r}"
        )
    assert counter("long") == long_c0, (
        f"/long backend was invoked during {long_checks} in-window GETs: "
        f"counter {counter('long')!r} != {long_c0!r}"
    )
    survived = time.monotonic() - long_created
    assert survived > 2 * _SHORT_TTL, (
        f"/long entry only spanned {survived:.0f}s -- not enough to separate the two TTLs"
    )

    # ---- FlushStageCache mid-window evicts /long --------------------------------------------
    flush = apigw.flush_stage_cache(restApiId=api_id, stageName=stage)
    flushed_at = time.monotonic()
    assert flush["ResponseMetadata"]["HTTPStatusCode"] == 202, f"FlushStageCache returned {flush!r}"
    post_n = None
    flush_deadline = flushed_at + 90
    while time.monotonic() < flush_deadline:
        st, _, b = _get(long_url)
        assert st == 200, f"/long after flush returned {st} {b!r}"
        if _n(b) != long_n:
            post_n = _n(b)
            break
        time.sleep(1)
    age_at_miss = time.monotonic() - long_created
    assert post_n is not None, (
        f"/long kept serving the pre-flush entry n={long_n!r} for 90s after FlushStageCache"
    )
    assert age_at_miss < _LONG_TTL - 30, (
        f"the post-flush miss came {age_at_miss:.0f}s after the entry was cached -- too close to "
        f"the {_LONG_TTL}s TTL to attribute it to the flush"
    )
    assert post_n == counter("long") == long_c0 + 1, (
        f"post-flush miss should invoke the backend exactly once: body n={post_n!r}, "
        f"counter {counter('long')!r}, pre-flush counter {long_c0!r}"
    )
    # ...and caching resumes on a NEW entry. FlushStageCache is asynchronous (202), and an entry
    # stored by the first post-flush miss can be evicted again by the still-running flush, so
    # wait for a settled hit rather than reading the very next response.
    final_n, _ = _wait_for_hit(long_url, lambda: counter("long"), _SETTLE_TIMEOUT_S, k=3)
    assert final_n >= post_n > long_n, (
        f"post-flush cache settled on n={final_n!r}; expected a fresh entry (>= {post_n!r}, "
        f"pre-flush {long_n!r})"
    )
    assert counter("long") == final_n, (
        f"settled post-flush hit n={final_n!r} but the backend counter reads {counter('long')!r}"
    )



def _left(start: float) -> float:
    return _BUDGET_S - (time.monotonic() - start)


def _get(url: str, headers: dict | None = None, timeout_s: float = 15.0) -> tuple[int, dict, str]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read().decode()


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
        time.sleep(10)
    return status


def _n(body: str) -> int:
    """The backend counter value the response carries -- the part of the body the cache holds."""
    return int(json.loads(body)["n"])


def _wait_for_hit(url: str, counter, timeout_s: float, k: int = 3) -> tuple[int, float]:
    """Poll until `k` consecutive GETs carry the same counter value with no backend invocation
    -- a settled cache hit. Returns (n, monotonic time that value was first observed)."""
    deadline = time.monotonic() + timeout_s
    run: list = []
    while time.monotonic() < deadline:
        t = time.monotonic()
        st, _, b = _get(url)
        c = counter()
        n = _n(b) if st == 200 else None
        if n is not None and run and run[-1][0] == n and run[-1][1] == c:
            run.append((n, c, t))
            if len(run) >= k:
                return n, run[0][2]
        else:
            run = [(n, c, t)] if n is not None else []
        time.sleep(1)
    raise AssertionError(f"{url}: never observed {k} consecutive cache hits within {timeout_s}s; last {run[-1:]!r}")


def _create_counter_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-xsvc-msett-ttl-")
    ddb.create_table(TableName=table, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return table


def _delete_table(ddb, table: str) -> None:
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    ddb.delete_table(TableName=table)


def _create_integration_role(ctx, table: str) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-msett-ttl-")
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


def _create_counter_api(ctx, table: str, role_arn: str, paths: tuple[str, ...]) -> str:
    """GET /<path> -> DynamoDB UpdateItem on key <path> (ADD n 1, UPDATED_NEW) -> {"n", "rid"}."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-xsvc-msett-ttl-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    for path in paths:
        res = apigw.create_resource(restApiId=api_id, parentId=root, pathPart=path)["id"]
        apigw.put_method(restApiId=api_id, resourceId=res, httpMethod="GET", authorizationType="NONE")
        template = json.dumps({
            "TableName": table, "Key": {"pk": {"S": path}},
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

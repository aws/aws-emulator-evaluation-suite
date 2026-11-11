"""deep-apigw-integration-request-authorizer-cache-keys-on-every-identity-source."""
from __future__ import annotations

import http.client
import json
import textwrap
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigw-integration-request-authorizer-cache-keys-on-every-identity-source"
GROUP = "authorizers"
SERVICES = ["apigateway", "lambda"]

# Allows the whole API and mints a fresh marker per INVOCATION, so a response carrying an
# earlier marker was served from the authorizer cache.
_AUTHORIZER = """
import uuid


def lambda_handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    query = event.get("queryStringParameters") or {}
    return {
        "principalId": "p-" + headers.get("x-user", ""),
        "policyDocument": {"Version": "2012-10-17", "Statement": [{
            "Action": "execute-api:Invoke", "Effect": "Allow",
            "Resource": event["methodArn"].split("/")[0] + "/*"}]},
        "context": {"minted": uuid.uuid4().hex, "user": headers.get("x-user", ""),
                    "org": query.get("org", "")},
    }
"""

_RESPONSE = ('{"minted": "$context.authorizer.minted", "user": "$context.authorizer.user", '
             '"org": "$context.authorizer.org"}')


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A REQUEST authorizer with a header and a query-string identity source caches on the pair: a repeated
    pair hits the cache, changing either part misses, and a request missing either part is 401."""
    auth_fn = _create_lambda(ctx, _AUTHORIZER)
    api_id, root_id = _create_rest_api(ctx, "req-authz-cache")
    ag = ctx.client("apigateway")
    account = _account_id(ctx)
    auth_id = _c(ag.create_authorizer, restApiId=api_id, name=_xname(ctx, "authz"),
                 type="REQUEST",
                 identitySource="method.request.header.X-User, method.request.querystring.org",
                 authorizerUri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/"
                                f"functions/{auth_fn['arn']}/invocations"),
                 authorizerResultTtlInSeconds=300)["id"]
    _allow_apigw_invoke(ctx, auth_fn["name"],
                        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/authorizers/{auth_id}")
    rid = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="who")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=rid, httpMethod="GET",
       authorizationType="CUSTOM", authorizerId=auth_id)
    _c(ag.put_integration, restApiId=api_id, resourceId=rid, httpMethod="GET", type="MOCK",
       requestTemplates={"application/json": '{"statusCode": 200}'})
    _c(ag.put_method_response, restApiId=api_id, resourceId=rid, httpMethod="GET",
       statusCode="200")
    _c(ag.put_integration_response, restApiId=api_id, resourceId=rid, httpMethod="GET",
       statusCode="200", selectionPattern="",
       responseTemplates={"application/json": _RESPONSE})
    _deploy_stage(ctx, api_id, "c")
    base = _rest_invoke_url(ctx, api_id, "c", "/who")

    def call(user=None, org=None, noise=None):
        query = {}
        if org is not None:
            query["org"] = org
        if noise is not None:
            query["noise"] = noise
        hdrs = [("Accept", "application/json")]
        if user is not None:
            hdrs.append(("X-User", user))
        if noise is not None:
            hdrs.append(("X-Noise", noise))
        url = base + (("?" + urllib.parse.urlencode(query)) if query else "")
        return _raw_request("GET", url, hdrs)

    def body(result, why):
        status, _h, text = result
        assert status == 200, f"{why}: expected 200, got {status}: {text!r}"
        return json.loads(text)

    def settled(user, org):
        """First response for a pair, then repeats until the cache entry is readable.
        A just-written cache entry can miss once within ~2s of the cold call;
        it never recurs, so two consecutive equal markers mark the entry as settled."""
        first = body(call(user, org), f"cold call {user}/{org}")
        prev = first["minted"]
        for _ in range(8):
            time.sleep(1.0)
            cur = body(call(user, org), f"settle {user}/{org}")["minted"]
            if cur == prev:
                return first, cur
            prev = cur
        raise AssertionError(f"the cache entry for {user}/{org} never settled; last marker {prev!r}")

    u1, u2 = ctx.unique_name("u1"), ctx.unique_name("u2")
    o1, o2 = ctx.unique_name("o1"), ctx.unique_name("o2")

    _poll(lambda: call(u1, o1), lambda r: r[0] == 200, "GET /who through the REQUEST authorizer")
    first, m11 = settled(u1, o1)
    assert first["user"] == u1 and first["org"] == o1, (
        f"the authorizer's context must carry the identity it was invoked with, got {first!r}")

    # Non-identity inputs are not part of the key: same pair plus noise is a cache HIT.
    for i in range(2):
        hit = body(call(u1, o1, noise=ctx.unique_name(f"n{i}")), "same pair, different noise")
        assert hit["minted"] == m11, (
            f"a non-identity header/query change must not bust the cache: marker "
            f"{hit['minted']!r} != cached {m11!r}")

    # Changing ONLY the query-string part is a miss, evaluated for the new pair.
    q_first, m12 = settled(u1, o2)
    assert q_first["minted"] != m11 and m12 != m11, (
        f"changing only the 'org' identity source must be a cache MISS, but {u1}/{o2} was "
        f"served the {u1}/{o1} marker {m11!r}")
    assert q_first["org"] == o2, f"the fresh decision must be for org {o2!r}, got {q_first!r}"

    # Changing ONLY the header part is a miss too.
    h_first, m21 = settled(u2, o1)
    assert h_first["minted"] != m11 and h_first["minted"] != m12 and h_first["user"] == u2, (
        f"changing only the 'X-User' identity source must be a cache MISS evaluated for "
        f"{u2!r}, got {h_first!r} (earlier markers {m11!r}, {m12!r})")

    # Entries coexist: the original pair is still served its original decision.
    again = body(call(u1, o1), "original pair after the misses")
    assert again["minted"] == m11 and again["org"] == o1, (
        f"the {u1}/{o1} entry must survive the other pairs' entries, got {again!r}")

    # A missing identity-source part is a 401 before any authorizer decision.
    for why, result in (("no X-User header", call(None, o1)), ("no org query", call(u1, None))):
        status, headers, text = result
        assert status == 401, f"{why}: expected 401, got {status}: {text!r}"
        assert headers.get("x-amzn-errortype") == "UnauthorizedException", (
            f"{why}: expected UnauthorizedException, got {headers.get('x-amzn-errortype')!r}")
        assert json.loads(text) == {"message": "Unauthorized"}, f"{why}: body {text!r}"
        assert "minted" not in text, f"{why}: the integration ran: {text!r}"


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
    """Poll probe() to a condition (stage/IAM/permission propagation), tolerating
    connection errors while execute-api DNS settles."""
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
    """HTTP via http.client so a header can be sent TWICE (urllib folds duplicates).
    Returns (status, lower-cased headers, text); a 4xx/5xx is a result, not an exception."""
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


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, name):
    """delete_function does not remove /aws/lambda/<fn>, and a late log flush can recreate it
    after a single delete — so reap in rounds and re-check, declaring a leak if it persists."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    for _ in range(6):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(5)
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in found):
            return
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_lambda(ctx, handler_code, env=None):
    """Execution role (logs only) + python3.12 function; both teardowns registered at create.
    The log-group reap is registered BEFORE the function so LIFO runs it after the delete."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Path="/sim2real/",
                               Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
            "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*"}]}))
    name = _xname(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kw = {"FunctionName": name, "Runtime": "python3.12", "Role": role_arn,
          "Handler": "lambda_function.lambda_handler", "Code": {"ZipFile": buf.getvalue()},
          "Timeout": 15, "MemorySize": 128, "Tags": dict(_TAGS)}
    if env:
        kw["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(**kw)["FunctionArn"]
            break
        except ClientError as exc:
            # IAM propagation: a brand-new role is not yet assumable by Lambda.
            if (exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException"
                    or time.monotonic() >= deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": name, "arn": arn}


def _allow_apigw_invoke(ctx, fn_name, source_arn):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com", SourceArn=source_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

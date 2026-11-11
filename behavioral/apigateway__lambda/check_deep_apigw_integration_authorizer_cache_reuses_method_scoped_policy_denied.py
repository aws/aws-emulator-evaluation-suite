"""deep-apigw-integration-authorizer-cache-reuses-method-scoped-policy-denied."""
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

CHECK = "deep-apigw-integration-authorizer-cache-reuses-method-scoped-policy-denied"
GROUP = "authorizers"
SERVICES = ["apigateway", "lambda"]

# Allows EXACTLY the methodArn it was invoked for, and mints a fresh marker per invocation so
# the backend can tell a cached decision from a fresh one.
_AUTHORIZER = """
import uuid


def lambda_handler(event, context):
    return {
        "principalId": "p-" + event.get("authorizationToken", ""),
        "policyDocument": {"Version": "2012-10-17", "Statement": [{
            "Action": "execute-api:Invoke", "Effect": "Allow",
            "Resource": event["methodArn"]}]},
        "context": {"minted": uuid.uuid4().hex, "forArn": event["methodArn"]},
    }
"""

_BACKEND = """
import json


def lambda_handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"path": event["path"],
                                "authorizer": event["requestContext"].get("authorizer")})}
"""

_TTL = 300


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A cached TOKEN authorizer policy scoped to one methodArn denies the same token on a sibling
    method (403) while a fresh token there is allowed; flushing the authorizer cache removes the denial."""
    auth_fn = _create_lambda(ctx, _AUTHORIZER)
    backend = _create_lambda(ctx, _BACKEND)
    api_id, root_id = _create_rest_api(ctx, "authz-cache")
    ag = ctx.client("apigateway")
    account = _account_id(ctx)
    auth_id = _c(ag.create_authorizer, restApiId=api_id, name=_xname(ctx, "authz"),
                 type="TOKEN", identitySource="method.request.header.Authorization",
                 authorizerUri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/"
                                f"functions/{auth_fn['arn']}/invocations"),
                 authorizerResultTtlInSeconds=_TTL)["id"]
    _allow_apigw_invoke(ctx, auth_fn["name"],
                        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/authorizers/{auth_id}")
    backend_uri = (f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
                   f"{backend['arn']}/invocations")
    for part in ("a", "b"):
        rid = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart=part)["id"]
        _c(ag.put_method, restApiId=api_id, resourceId=rid, httpMethod="GET",
           authorizationType="CUSTOM", authorizerId=auth_id)
        _c(ag.put_integration, restApiId=api_id, resourceId=rid, httpMethod="GET",
           type="AWS_PROXY", integrationHttpMethod="POST", uri=backend_uri)
    _allow_apigw_invoke(ctx, backend["name"],
                        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/GET/*")
    _deploy_stage(ctx, api_id, "s")

    def call(part, token):
        return _raw_request("GET", _rest_invoke_url(ctx, api_id, "s", f"/{part}"),
                            [("Authorization", token), ("Accept", "application/json")])

    def minted(text):
        return (json.loads(text).get("authorizer") or {}).get("minted")

    t1 = ctx.unique_name("tok1")
    t2 = ctx.unique_name("tok2")

    # Warm-up on /a with t1 is the positive control; it also seeds the cache for t1.
    _poll(lambda: call("a", t1), lambda r: r[0] == 200, "GET /a with token 1")
    a1_status, _h, a1_text = call("a", t1)
    assert a1_status == 200, f"GET /a with token 1 expected 200, got {a1_status}: {a1_text!r}"
    m1 = minted(a1_text)
    assert m1, f"the authorizer context never reached the backend: {a1_text!r}"
    a2_status, _h, a2_text = call("a", t1)
    assert a2_status == 200 and minted(a2_text) == m1, (
        f"a repeat call with the same token inside the {_TTL}s TTL must be served the CACHED "
        f"decision (same marker {m1!r}), got {a2_status} marker {minted(a2_text)!r}")

    b_status, b_headers, b_text = call("b", t1)
    assert b_status == 403, (
        f"token 1's cached policy allows only GET /a, so GET /b with token 1 must be refused "
        f"from the cache with 403, got {b_status}: {b_text[:300]!r}")
    assert b_headers.get("x-amzn-errortype") == "AccessDeniedException", (
        f"expected AccessDeniedException, got {b_headers.get('x-amzn-errortype')!r}")
    assert json.loads(b_text) == {
            "Message": "User is not authorized to access this resource because no "
                       "identity-based policy allows the execute-api:Invoke action"}, (
        f"a policy that simply does not cover the method is the non-explicit-deny message, "
        f"got {b_text!r}")
    assert "authorizer" not in b_text, f"the backend ran for a refused request: {b_text!r}"

    # A different identity-source value is a cache MISS: evaluated fresh for /b, allowed.
    fb_status, _h, fb_text = call("b", t2)
    assert fb_status == 200, f"GET /b with a fresh token must be allowed, got {fb_status}: {fb_text!r}"
    fb_auth = json.loads(fb_text)["authorizer"]
    assert fb_auth.get("minted") is not None and fb_auth.get("minted") != m1, (
        f"a new token must invoke the authorizer anew, but the marker was {fb_auth.get('minted')!r}")
    assert fb_auth.get("forArn", "").endswith("/s/GET/b"), (
        f"the fresh evaluation must have been for GET /b, got methodArn {fb_auth.get('forArn')!r}")

    # Break the cache, and exactly that denial disappears: token 1 is re-evaluated for /b.
    _c(ag.flush_stage_authorizers_cache, restApiId=api_id, stageName="s")
    fl_status, _h, fl_text = _poll(lambda: call("b", t1), lambda r: r[0] == 200,
                                   "GET /b with token 1 after FlushStageAuthorizersCache",
                                   timeout_s=120.0)
    assert minted(fl_text) is not None and minted(fl_text) != m1, (
        f"after the flush token 1 must be evaluated anew, marker was {minted(fl_text)!r}")


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

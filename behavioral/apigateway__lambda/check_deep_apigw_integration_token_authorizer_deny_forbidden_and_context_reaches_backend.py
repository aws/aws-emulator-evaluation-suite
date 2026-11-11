"""deep-apigw-integration-token-authorizer-deny-forbidden-and-context-reaches-backend."""
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

CHECK = "deep-apigw-integration-token-authorizer-deny-forbidden-and-context-reaches-backend"
GROUP = "authorizers"
SERVICES = ["apigateway", "lambda"]

# Token grammar: "allow-<who>" -> Allow, "deny-<who>" -> Deny, "unauth" -> raise
# "Unauthorized" (the documented way for a TOKEN authorizer to produce a 401).
_AUTHORIZER = """
def lambda_handler(event, context):
    token = event.get("authorizationToken", "")
    if token == "unauth":
        raise Exception("Unauthorized")
    kind, _, who = token.partition("-")
    effect = {"allow": "Allow", "deny": "Deny"}.get(kind)
    if effect is None:
        raise Exception("Unauthorized")
    return {
        "principalId": "user-" + who,
        "policyDocument": {"Version": "2012-10-17", "Statement": [{
            "Action": "execute-api:Invoke", "Effect": effect,
            "Resource": event["methodArn"]}]},
        "context": {"tenant": who, "tier": "gold"},
    }
"""

_BACKEND = """
import json


def lambda_handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"backend": "ran",
                                "authorizer": event["requestContext"].get("authorizer")})}
"""


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A TOKEN authorizer's Allow reaches the backend with its principalId and context; a Deny is 403
    AccessDeniedException with no backend output; Unauthorized and a missing token are 401."""
    auth_fn = _create_lambda(ctx, _AUTHORIZER)
    backend = _create_lambda(ctx, _BACKEND)
    api_id, root_id = _create_rest_api(ctx, "token-authz")
    ag = ctx.client("apigateway")
    account = _account_id(ctx)
    auth_id = _c(ag.create_authorizer, restApiId=api_id, name=_xname(ctx, "authz"),
                 type="TOKEN", identitySource="method.request.header.Authorization",
                 authorizerUri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/"
                                f"functions/{auth_fn['arn']}/invocations"),
                 authorizerResultTtlInSeconds=0)["id"]
    _allow_apigw_invoke(ctx, auth_fn["name"],
                        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/authorizers/{auth_id}")
    rid = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="secure")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=rid, httpMethod="GET",
       authorizationType="CUSTOM", authorizerId=auth_id)
    _c(ag.put_integration, restApiId=api_id, resourceId=rid, httpMethod="GET", type="AWS_PROXY",
       integrationHttpMethod="POST",
       uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{backend['arn']}/invocations"))
    _allow_apigw_invoke(ctx, backend["name"],
                        f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/GET/secure")
    _deploy_stage(ctx, api_id, "api")
    url = _rest_invoke_url(ctx, api_id, "api", "/secure")

    who = ctx.unique_name("w")

    def call(token=None):
        hdrs = [("Accept", "application/json")]
        if token is not None:
            hdrs.append(("Authorization", token))
        return _raw_request("GET", url, hdrs)

    # Positive control: Allow reaches the backend carrying the authorizer's context.
    status, _h, text = _poll(lambda: call(f"allow-{who}"), lambda r: r[0] == 200,
                             "Allow token through the TOKEN authorizer")
    body = json.loads(text)
    assert body.get("backend") == "ran", f"Allow must reach the backend, got {body!r}"
    authz = body.get("authorizer") or {}
    assert authz.get("principalId") == f"user-{who}", (
        f"requestContext.authorizer.principalId must be the authorizer's principalId, got "
        f"{authz.get('principalId')!r} (authorizer block {authz!r})")
    assert authz.get("tenant") == who and authz.get("tier") == "gold", (
        f"the authorizer's context keys must reach the backend in requestContext.authorizer, "
        f"got {authz!r}")

    d_status, d_headers, d_text = call(f"deny-{who}")
    assert d_status == 403, f"a Deny policy must be a 403, got {d_status}: {d_text[:300]!r}"
    assert d_headers.get("x-amzn-errortype") == "AccessDeniedException", (
        f"a Deny must be classified AccessDeniedException, got {d_headers.get('x-amzn-errortype')!r}")
    assert json.loads(d_text) == {
            "Message": "User is not authorized to access this resource with an explicit deny "
                       "in an identity-based policy"}, (
        f"unexpected explicit-deny body {d_text!r}")
    assert "backend" not in d_text, f"the backend ran behind a Deny: {d_text!r}"

    u_status, u_headers, u_text = call("unauth")
    assert u_status == 401, f"an authorizer raising 'Unauthorized' must be a 401, got {u_status}: {u_text!r}"
    assert u_headers.get("x-amzn-errortype") == "UnauthorizedException", (
        f"expected UnauthorizedException, got {u_headers.get('x-amzn-errortype')!r}")
    assert json.loads(u_text) == {"message": "Unauthorized"}, f"unexpected 401 body {u_text!r}"

    m_status, m_headers, m_text = call(None)
    assert m_status == 401, f"a request with no Authorization header must be a 401, got {m_status}: {m_text!r}"
    assert m_headers.get("x-amzn-errortype") == "UnauthorizedException", (
        f"expected UnauthorizedException, got {m_headers.get('x-amzn-errortype')!r}")
    assert "backend" not in m_text, f"the backend ran without an identity source: {m_text!r}"

    # The refusals did not poison the method: Allow still works afterwards.
    again_status, _ah, again_text = call(f"allow-{who}")
    assert again_status == 200 and json.loads(again_text).get("backend") == "ran", (
        f"Allow after the refusals must still reach the backend, got {again_status}: {again_text!r}")


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

"""deep-apigw-integration-lambda-error-selection-pattern-maps-status."""
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

CHECK = "deep-apigw-integration-lambda-error-selection-pattern-maps-status"
GROUP = "error-propagation"
SERVICES = ["apigateway", "lambda"]

# The function succeeds or raises depending on `mode`; a raised exception becomes the
# integration response {"errorMessage", "errorType", ...} that selectionPattern is matched on.
_FN = """
def lambda_handler(event, context):
    mode = event.get("mode")
    item = event.get("id")
    if mode == "notfound":
        raise LookupError("NotFound: item " + item)
    if mode == "invalid":
        raise ValueError("Invalid: quantity for " + item)
    if mode == "wrapped":
        raise RuntimeError("upstream said NotFound: item " + item)
    if mode == "boom":
        raise RuntimeError("kaboom " + item)
    return {"ok": True, "id": item}
"""

_REQ = '{"mode": "$input.params(\'mode\')", "id": "$input.params(\'id\')"}'


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A non-proxy Lambda integration maps function errors by a whole-message selectionPattern match on
    errorMessage (NotFound: to 404, Invalid: to 400); a prefixed or unmatched error falls through to
    the default 200 integration response."""
    fn = _create_lambda(ctx, _FN)
    api_id, root_id = _create_rest_api(ctx, "lambda-errors")
    ag = ctx.client("apigateway")
    things = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="things")["id"]
    tid = _c(ag.create_resource, restApiId=api_id, parentId=things, pathPart="{id}")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=tid, httpMethod="GET", authorizationType="NONE")
    _c(ag.put_integration, restApiId=api_id, resourceId=tid, httpMethod="GET", type="AWS",
       integrationHttpMethod="POST",
       uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"),
       requestTemplates={"application/json": _REQ})
    for code in ("200", "400", "404"):
        _c(ag.put_method_response, restApiId=api_id, resourceId=tid, httpMethod="GET",
           statusCode=code)
    _c(ag.put_integration_response, restApiId=api_id, resourceId=tid, httpMethod="GET",
       statusCode="200")
    _c(ag.put_integration_response, restApiId=api_id, resourceId=tid, httpMethod="GET",
       statusCode="404", selectionPattern="NotFound:.*",
       responseTemplates={"application/json":
                          '{"error": "not_found", '
                          '"detail": "$util.escapeJavaScript($input.path(\'$.errorMessage\'))"}'})
    _c(ag.put_integration_response, restApiId=api_id, resourceId=tid, httpMethod="GET",
       statusCode="400", selectionPattern="Invalid:.*",
       responseTemplates={"application/json":
                          '{"error": "invalid", "type": "$input.path(\'$.errorType\')"}'})
    account = _account_id(ctx)
    _allow_apigw_invoke(ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*")
    _deploy_stage(ctx, api_id, "v1")

    item = ctx.unique_name("i")
    base = _rest_invoke_url(ctx, api_id, "v1", f"/things/{item}")

    def get(mode):
        return _raw_request("GET", f"{base}?mode={mode}", [("Accept", "application/json")])

    # Positive control: the success path returns the function's value through the 200.
    ok_status, _oh, ok_text = _poll(lambda: get("ok"), lambda r: r[0] == 200,
                                    "GET ?mode=ok through the Lambda integration")
    assert json.loads(ok_text) == {"ok": True, "id": item}, f"success body was {ok_text!r}"

    nf_status, _nh, nf_text = get("notfound")
    assert nf_status == 404, (
        f"an errorMessage matching 'NotFound:.*' must select the 404 integration response, "
        f"got {nf_status}: {nf_text[:300]!r}")
    nf = json.loads(nf_text)
    assert nf.get("error") == "not_found", f"404 must be rendered by its own template: {nf!r}"
    assert nf.get("detail") == f"NotFound: item {item}", (
        f"the 404 template's $input.path('$.errorMessage') must carry the function's message, "
        f"got {nf.get('detail')!r}")

    inv_status, _ih, inv_text = get("invalid")
    assert inv_status == 400, (
        f"an errorMessage matching 'Invalid:.*' must select the 400 integration response, "
        f"got {inv_status}: {inv_text[:300]!r}")
    assert json.loads(inv_text) == {"error": "invalid", "type": "ValueError"}, (
        f"the 400 template must render errorType from the function error, got {inv_text!r}")

    wr_status, _wh, wr_text = get("wrapped")
    assert wr_status == 200, (
        f"selectionPattern must match the WHOLE errorMessage: 'upstream said NotFound: ...' "
        f"must NOT select the 'NotFound:.*' 404 but fall through to the default 200, got "
        f"{wr_status}: {wr_text[:300]!r}")
    wr = json.loads(wr_text)
    assert wr.get("errorMessage") == f"upstream said NotFound: item {item}", (
        f"the default response must pass the Lambda error document through, got {wr!r}")

    b_status, _bh, b_text = get("boom")
    assert b_status == 200, (
        f"an error matching no selectionPattern is served by the DEFAULT integration response "
        f"(200), got {b_status}: {b_text[:300]!r}")
    boom = json.loads(b_text)
    assert boom.get("errorMessage") == f"kaboom {item}", f"unmatched error body was {boom!r}"
    assert boom.get("errorType") == "RuntimeError", f"unmatched error body was {boom!r}"
    assert "ok" not in boom, f"the success value leaked into an error response: {boom!r}"


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

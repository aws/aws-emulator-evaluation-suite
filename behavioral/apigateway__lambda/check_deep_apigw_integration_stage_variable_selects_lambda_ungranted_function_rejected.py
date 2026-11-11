"""deep-apigw-integration-stage-variable-selects-lambda-ungranted-function-rejected."""
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

CHECK = "deep-apigw-integration-stage-variable-selects-lambda-ungranted-function-rejected"
GROUP = "deployments-stages"
SERVICES = ["apigateway", "lambda"]

_FN = """
import json
import os


def lambda_handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"color": os.environ["COLOR"],
                                "fn": context.function_name,
                                "fnVar": (event.get("stageVariables") or {}).get("fn")})}
"""


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """One deployment whose Lambda URI uses ${stageVariables.fn} invokes a different function per
    stage; a stage resolving to a function without an API Gateway invoke grant answers 500 and the
    function never runs, and granting that one function makes the same stage serve it."""
    fns = {color: _create_lambda(ctx, _FN, env={"COLOR": color})
           for color in ("blue", "green", "red")}
    api_id, root_id = _create_rest_api(ctx, "stagevar-fn")
    ag = ctx.client("apigateway")
    account = _account_id(ctx)
    rid = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="color")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=rid, httpMethod="GET", authorizationType="NONE")
    _c(ag.put_integration, restApiId=api_id, resourceId=rid, httpMethod="GET", type="AWS_PROXY",
       integrationHttpMethod="POST",
       uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"arn:aws:lambda:{ctx.region}:{account}:function:${{stageVariables.fn}}/invocations"))
    source_arn = f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/GET/color"
    for color in ("blue", "green"):  # red deliberately NOT granted
        _allow_apigw_invoke(ctx, fns[color]["name"], source_arn)

    dep_id = _c(ag.create_deployment, restApiId=api_id)["id"]
    for color in ("blue", "green", "red"):
        _c(ag.create_stage, restApiId=api_id, stageName=color, deploymentId=dep_id,
           variables={"fn": fns[color]["name"]})
        ctx.on_cleanup(lambda s=color: _c(ag.delete_stage, restApiId=api_id, stageName=s))

    def call(stage):
        return _raw_request("GET", _rest_invoke_url(ctx, api_id, stage, "/color"),
                            [("Accept", "application/json")])

    for color in ("blue", "green"):
        _status, _h, text = _poll(lambda c=color: call(c), lambda r: r[0] == 200,
                                  f"GET /{color}/color")
        body = json.loads(text)
        assert body == {"color": color, "fn": fns[color]["name"], "fnVar": fns[color]["name"]}, (
            f"stage {color!r} must invoke the function its stage variable names "
            f"({fns[color]['name']!r}), got {body!r}")

    r_status, r_headers, r_text = call("red")
    assert r_status == 500, (
        f"a stage variable resolving to a function without an API Gateway invoke grant must "
        f"be a 500, got {r_status}: {r_text[:300]!r}")
    assert json.loads(r_text) == {"message": "Internal server error"}, f"unexpected body {r_text!r}"
    assert r_headers.get("x-amzn-errortype") == "InternalServerErrorException", (
        f"expected InternalServerErrorException, got {r_headers.get('x-amzn-errortype')!r}")
    assert "color" not in r_text, f"the ungranted function's output leaked: {r_text!r}"

    logs = ctx.client("logs")
    red_group = f"/aws/lambda/{fns['red']['name']}"
    for _ in range(4):  # a settle window: the effect must STAY absent, not be absent once
        groups = logs.describe_log_groups(logGroupNamePrefix=red_group).get("logGroups", [])
        assert not any(g["logGroupName"] == red_group for g in groups), (
            f"{red_group} exists, so the ungranted red function WAS invoked behind the 500")
        time.sleep(4)

    # Fix exactly one thing — the red function's resource policy — and the red stage serves it.
    _allow_apigw_invoke(ctx, fns["red"]["name"], source_arn)
    _s, _h, fixed = _poll(lambda: call("red"), lambda r: r[0] == 200,
                          "GET /red/color after granting the red function", timeout_s=180.0)
    assert json.loads(fixed) == {"color": "red", "fn": fns["red"]["name"],
                                 "fnVar": fns["red"]["name"]}, f"red stage served {fixed!r}"


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

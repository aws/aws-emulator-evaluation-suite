"""deep-apigw-integration-lambda-non-proxy-vtl-maps-request-and-response."""
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

CHECK = "deep-apigw-integration-lambda-non-proxy-vtl-maps-request-and-response"
GROUP = "data-format"
SERVICES = ["apigateway", "lambda"]

# Non-proxy: the function receives WHATEVER the request template rendered, and its return
# value is the integration response the response template then reshapes.
_ECHO = """
def lambda_handler(event, context):
    return {"received": event, "fn": "echo"}
"""

_REQUEST_TEMPLATE = (
    "{\n"
    '  "payload": $input.json(\'$.order\'),\n'
    '  "tenant": "$input.params(\'X-Tenant\')",\n'
    '  "q": "$input.params(\'q\')",\n'
    '  "id": "$input.params(\'id\')",\n'
    '  "note": "$util.escapeJavaScript($input.params(\'note\'))",\n'
    '  "stage": "$context.stage",\n'
    '  "method": "$context.httpMethod"\n'
    "}"
)

_RESPONSE_TEMPLATE = (
    "{\n"
    '  "shape": "mapped",\n'
    '  "tenant": "$input.path(\'$.received.tenant\')",\n'
    '  "total": $input.json(\'$.received.payload.total\'),\n'
    '  "raw": "$util.escapeJavaScript($input.json(\'$.received\'))"\n'
    "}"
)


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A non-proxy Lambda integration's request template builds the function's event ($input.json,
    $input.params, $util.escapeJavaScript) and its response template maps the return value; the
    client reads back exactly the event the template should have rendered."""
    fn = _create_lambda(ctx, _ECHO)
    api_id, root_id = _create_rest_api(ctx, "vtl-lambda")
    ag = ctx.client("apigateway")
    orders_id = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="orders")["id"]
    oid = _c(ag.create_resource, restApiId=api_id, parentId=orders_id, pathPart="{id}")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=oid, httpMethod="POST",
       authorizationType="NONE")
    _c(ag.put_integration, restApiId=api_id, resourceId=oid, httpMethod="POST", type="AWS",
       integrationHttpMethod="POST",
       uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"),
       requestTemplates={"application/json": _REQUEST_TEMPLATE},
       passthroughBehavior="WHEN_NO_TEMPLATES")
    _c(ag.put_method_response, restApiId=api_id, resourceId=oid, httpMethod="POST",
       statusCode="200")
    _c(ag.put_integration_response, restApiId=api_id, resourceId=oid, httpMethod="POST",
       statusCode="200", responseTemplates={"application/json": _RESPONSE_TEMPLATE})
    account = _account_id(ctx)
    _allow_apigw_invoke(ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*")
    _deploy_stage(ctx, api_id, "prod")

    order_id = ctx.unique_name("o")
    tenant = ctx.unique_name("t")
    order = {"total": 42, "items": [{"sku": "a-1", "qty": 2}], "gift": True}
    note = 'said "hi" \\ twice'
    query = urllib.parse.urlencode({"q": "find-me", "note": note})
    url = _rest_invoke_url(ctx, api_id, "prod", f"/orders/{order_id}") + f"?{query}"
    body = json.dumps({"order": order, "ignored": "not-in-template"}).encode()
    hdrs = [("Content-Type", "application/json"), ("X-Tenant", tenant)]

    status, _h, text = _poll(lambda: _raw_request("POST", url, hdrs, body=body),
                             lambda r: r[0] == 200, "POST /orders/{id} through the AWS integration")
    out = json.loads(text)
    assert set(out) == {"shape", "tenant", "total", "raw"}, (
        f"the client must receive the RESPONSE-TEMPLATE document, not the function's raw "
        f"output; got keys {sorted(out)!r}: {text[:400]!r}")
    assert out["shape"] == "mapped" and "received" not in out, f"unmapped response: {out!r}"
    assert out["tenant"] == tenant, f"$input.path over the function output gave {out['tenant']!r}"
    assert out["total"] == 42, f"$input.json over the function output gave {out['total']!r}"

    received = json.loads(out["raw"])
    expected = {"payload": order, "tenant": tenant, "q": "find-me", "id": order_id,
                "note": note, "stage": "prod", "method": "POST"}
    assert received == expected, (
        f"the function must receive exactly the rendered request template.\n"
        f"  expected {expected!r}\n  received {received!r}")
    assert "ignored" not in json.dumps(received), (
        f"a body field the template never referenced reached the function: {received!r}")
    assert "httpMethod" not in received and "requestContext" not in received, (
        f"a non-proxy integration must not hand the function the proxy event: {received!r}")

    # $input.params of an ABSENT header renders as "" — the request still reaches Lambda.
    n_status, _nh, n_text = _raw_request("POST", url, [("Content-Type", "application/json")],
                                         body=body)
    assert n_status == 200, f"POST without X-Tenant expected 200, got {n_status}: {n_text[:300]!r}"
    n_received = json.loads(json.loads(n_text)["raw"])
    assert n_received.get("tenant") == "", (
        f"$input.params('X-Tenant') with no such header must render as the empty string, got "
        f"{n_received.get('tenant')!r}")
    assert n_received.get("payload") == order, (
        f"the rest of the rendering must be unaffected, got {n_received!r}")


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

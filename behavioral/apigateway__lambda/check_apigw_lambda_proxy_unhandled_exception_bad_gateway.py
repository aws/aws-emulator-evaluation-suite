"""apigw-lambda-proxy-unhandled-exception-bad-gateway."""
from __future__ import annotations

import json
import textwrap
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-lambda-proxy-unhandled-exception-bad-gateway"
GROUP = "error-propagation"
SERVICES = ["apigateway", "lambda"]

# The handler ALWAYS reports to the SQS side channel first, then either returns a
# well-formed proxy response or raises — so the side channel proves invocation on both
# legs, independent of whatever API Gateway does with the response.
_FN = """
import json
import os

import boto3

def lambda_handler(event, context):
    mode = (event.get("queryStringParameters") or {}).get("mode", "ok")
    marker = os.environ["MARKER"]
    boto3.client("sqs").send_message(
        QueueUrl=os.environ["QUEUE_URL"],
        MessageBody=json.dumps({"mode": mode, "marker": marker,
                                 "requestId": context.aws_request_id}),
    )
    if mode == "boom":
        raise RuntimeError("boom-" + marker)
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": marker, "mode": mode}),
    }
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A proxy handler that raises is answered with 502 {"message":"Internal server error"} although
    its SQS write before the raise lands; the /ok route on the same integration returns normally."""
    queue_url, queue_arn = _create_queue(ctx)
    marker = ctx.unique_name("m")
    fn = _create_lambda(ctx, _FN, env={"QUEUE_URL": queue_url, "MARKER": marker},
                        extra_actions=["sqs:SendMessage"], extra_resource=queue_arn)
    api_id, root_id = _create_rest_api(ctx, "lambda-boom")
    ag = ctx.client("apigateway")
    things = _c(ag.create_resource, restApiId=api_id, parentId=root_id, pathPart="things")["id"]
    _c(ag.put_method, restApiId=api_id, resourceId=things, httpMethod="GET",
       authorizationType="NONE")
    _c(ag.put_integration, restApiId=api_id, resourceId=things, httpMethod="GET",
       type="AWS_PROXY", integrationHttpMethod="POST",
       uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"))
    _allow_apigw_invoke(ctx, fn["name"],
                        f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*")
    _deploy_stage(ctx, api_id, "v1")

    base = _rest_invoke_url(ctx, api_id, "v1", "/things")

    def get(mode):
        return _raw_request("GET", f"{base}?mode={mode}", [("Accept", "application/json")])

    # ---- positive control: the same integration, a normal response ---------------------
    ok_status, _oh, ok_text = _poll(lambda: get("ok"), lambda r: r[0] == 200,
                                    "GET ?mode=ok through the Lambda proxy integration")
    assert json.loads(ok_text) == {"marker": marker, "mode": "ok"}, (
        f"expected the handler's own JSON through the proxy response, got {ok_text!r}"
    )

    # ---- the claim: an unhandled exception becomes 502 ----------------------------------
    boom_status, boom_headers, boom_text = get("boom")
    assert boom_status == 502, (
        f"expected 502 for a Lambda proxy integration whose handler raised, got "
        f"{boom_status}: {boom_text[:300]!r} (headers={boom_headers!r})"
    )
    assert json.loads(boom_text) == {"message": "Internal server error"}, (
        f"expected the fixed gateway body for an unhandled Lambda error, got {boom_text!r}"
    )

    # ---- the point of the check: the function still ran -------------------------------
    sqs = ctx.client("sqs")
    boom_messages = _poll(
        lambda: _drain_matching(sqs, queue_url, marker, "boom"),
        lambda found: len(found) >= 1, timeout_s=90.0, interval_s=3.0,
        description=("the raising invocation's SQS side-channel write, sent before the "
                     "raise — its absence would mean the function never ran at all"),
    )
    assert boom_messages[0]["marker"] == marker, (
        f"side channel must carry this run's marker {marker!r}, got {boom_messages[0]!r}"
    )


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
    """Poll probe() to a condition (stage/IAM/permission propagation, or a side-channel
    write), tolerating connection errors while execute-api DNS settles."""
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


def _drain_matching(sqs, queue_url, marker, mode):
    """Receive-and-delete everything currently visible whose marker/mode matches; never
    deletes a message that does not match, so a differently-shaped message is not silently
    discarded."""
    out = []
    for _ in range(6):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        messages = resp.get("Messages", [])
        if not messages:
            break
        for msg in messages:
            body = json.loads(msg["Body"])
            if body.get("marker") == marker and body.get("mode") == mode:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                out.append(body)
    return out


def _raw_request(method, url, header_pairs, body=None):
    """HTTP via http.client so a header can be sent TWICE (urllib folds duplicates).
    Returns (status, lower-cased headers, text); a 4xx/5xx is a result, not an exception."""
    import http.client
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


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, function_name: str, *, quiet_reads: int = 3, max_rounds: int = 12,
                    interval_s: float = 5.0) -> None:
    """delete_function never removes /aws/lambda/<fn>, and a late log flush can recreate it after
    a delete, so delete until the group has read absent several times running; raise if it keeps
    reappearing."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    quiet = 0
    for _ in range(max_rounds):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= quiet_reads:
                return
        time.sleep(interval_s)
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return queue_url, queue_arn


def _create_lambda(ctx, handler_code, env=None, extra_actions=None, extra_resource=None):
    """Execution role (logs, plus an optional extra action scoped to one resource) +
    python3.12 function; both teardowns registered at create. The log-group reap is
    registered BEFORE the function so LIFO runs it after the delete."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Path="/sim2real/",
                               Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    statements = [{"Effect": "Allow", "Action": [
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*"}]
    if extra_actions:
        statements.append({"Effect": "Allow", "Action": extra_actions,
                           "Resource": extra_resource})
    iam.put_role_policy(RoleName=role_name, PolicyName="perms", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": statements}))
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

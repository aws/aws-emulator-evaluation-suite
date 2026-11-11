"""request-authorizer-missing-one-of-two-identity-sources-unauthorized."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-authorizer-missing-one-of-two-identity-sources-unauthorized"
GROUP = 'authorizers'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


def _http(method, url, body=None, headers=None):
    """HTTP request via urllib; returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _poll_http(url, headers, want, timeout_s=120):
    """Poll the invoke URL until status == want (tolerating settling noise)."""
    status, body = None, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http("GET", url, headers=headers or {})
        except Exception:
            time.sleep(3)
            continue
        if status == want:
            return status, body
        time.sleep(3)
    return status, body


def _drain_queue(sqs, queue_url) -> int:
    """Receive-and-delete every visible message; return how many."""
    total = 0
    for _ in range(6):
        messages = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not messages:
            break
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        total += len(messages)
    return total


def _create_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"], api["ApiEndpoint"]


def _create_lambda_role(ctx, queue_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=TAGS_KV,
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": queue_arn},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy)
    )

    def _cleanup_role():
        try:
            for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return arn


def _create_lambda(ctx, handler_code, env, queue_arn):
    """Create a python Lambda; return {name, arn}. Registers teardown.

    CreateFunction is retried on "cannot be assumed" because IAM role propagation is asynchronous.
    """
    role_arn = _create_lambda_role(ctx, queue_arn)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": 30,
        "MemorySize": 128,
        "Tags": dict(TAGS),
        "Environment": {"Variables": env},
    }
    deadline = time.monotonic() + 60
    last_err = None
    arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            arn = lam.create_function(**kwargs)["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if arn is None:
        raise last_err or RuntimeError(f"failed to create lambda {name}")
    _deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= _deadline:
            raise AssertionError(f"lambda {name} active not met within 60s")
        time.sleep(2.0)
    return {"name": name, "arn": arn}


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _allow_apigw_invoke(ctx, fn_name, api_id, statement_id):
    lam = ctx.client("lambda")
    src = f"arn:aws:execute-api:{ctx.region}:{_account_id(ctx)}:{api_id}/*/*"
    try:
        lam.add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=src,
        )
    except ClientError as e:
        if "ResourceConflictException" not in str(e) and "already exists" not in str(e).lower():
            raise


def _invoke_url(ctx, api_endpoint, path, query=None, stage=None):
    p = path.lstrip("/")
    stg = stage or "$default"
    base = f"{ctx.stage_url(api_endpoint, stg)}/{p}"
    return f"{base}?{urllib.parse.urlencode(query)}" if query else base


#: One Lambda serves as both the authorizer and the backend, branching on the event shape: a
#: REQUEST-authorizer event carries "type": "REQUEST", a proxy event does not. Every authorizer
#: invocation writes one SQS message, which is the only way to COUNT invocations and prove the
#: gateway never called the Lambda at all when an identity source is missing.
_HANDLER_CODE = """
import json
import os

import boto3


def lambda_handler(event, context):
    if event.get("type") == "REQUEST":
        boto3.client("sqs").send_message(
            QueueUrl=os.environ["QUEUE_URL"],
            MessageBody=json.dumps({"identitySource": event.get("identitySource")}),
        )
        return {"isAuthorized": True}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"marker": os.environ["MARKER"]}),
    }
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A REQUEST authorizer with header and query-string identity sources returns 401 for a request
    missing either one without invoking the Lambda (counted via SQS); with both it invokes once.
    """
    marker = ctx.unique_name("sim2real-behav-authz-mis-")
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-authzcount-"), tags=dict(TAGS)
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    fn = _create_lambda(
        ctx, _HANDLER_CODE, {"QUEUE_URL": queue_url, "MARKER": marker}, queue_arn
    )

    agw = ctx.client("apigatewayv2")
    api_id, api_endpoint = _create_http_api(ctx)
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )
    authorizer_id = agw.create_authorizer(
        ApiId=api_id,
        Name=ctx.unique_name("sim2real-behav-authz-2src-"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["$request.header.x-sim2real-key", "$request.querystring.sig"],
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
        AuthorizerResultTtlInSeconds=0,  # no caching -> every request's invocation is countable
    )["AuthorizerId"]
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=api_id,
        RouteKey="GET /guarded",
        Target=f"integrations/{integration_id}",
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
    )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))
    _allow_apigw_invoke(ctx, fn["name"], api_id, "apigw-invoke")

    both_url = _invoke_url(ctx, api_endpoint, "/guarded", query={"sig": "s"})
    header_only_url = _invoke_url(ctx, api_endpoint, "/guarded")
    query_only_url = _invoke_url(ctx, api_endpoint, "/guarded", query={"sig": "s"})

    # Positive control: both identity sources present -> served, and invokes exactly once.
    status, body = _poll_http(both_url, {"x-sim2real-key": "k"}, want=200)
    assert status == 200, f"precondition: both identity sources present should be 200, got {status}: {body}"
    data = json.loads(body)
    assert data.get("marker") == marker, f"unexpected backend body: {data}"
    invocations = _drain_queue(sqs, queue_url)
    assert invocations == 1, (
        f"the positive control (both identity sources present) should invoke the authorizer "
        f"exactly once, got {invocations}"
    )

    # Missing the query-string identity source entirely (no "sig" param at all).
    status, _, body = _http("GET", header_only_url, headers={"x-sim2real-key": "k"})
    assert status == 401, (
        f"expected 401 Unauthorized when the querystring identity source 'sig' is absent, "
        f"got {status}: {body}"
    )
    payload = json.loads(body)
    assert payload == {"message": "Unauthorized"}, (
        f"expected the exact default-gateway-response body {{'message': 'Unauthorized'}}, "
        f"got {payload!r}"
    )
    invocations = _drain_queue(sqs, queue_url)
    assert invocations == 0, (
        f"a request missing one of two identity sources must be rejected WITHOUT invoking the "
        f"authorizer Lambda, but {invocations} invocation(s) landed on the side channel"
    )

    # Missing the header identity source entirely (no 'x-sim2real-key' header at all).
    status, _, body = _http("GET", query_only_url)
    assert status == 401, (
        f"expected 401 Unauthorized when the header identity source 'x-sim2real-key' is absent, "
        f"got {status}: {body}"
    )
    payload = json.loads(body)
    assert payload == {"message": "Unauthorized"}, (
        f"expected the exact default-gateway-response body {{'message': 'Unauthorized'}}, "
        f"got {payload!r}"
    )
    invocations = _drain_queue(sqs, queue_url)
    assert invocations == 0, (
        f"a request missing one of two identity sources must be rejected WITHOUT invoking the "
        f"authorizer Lambda, but {invocations} invocation(s) landed on the side channel"
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

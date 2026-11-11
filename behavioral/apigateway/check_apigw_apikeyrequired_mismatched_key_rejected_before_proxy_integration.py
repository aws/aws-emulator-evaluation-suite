"""apigw-apikeyrequired-mismatched-key-rejected-before-proxy-integration."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-apikeyrequired-mismatched-key-rejected-before-proxy-integration"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]

_BACKEND_CODE_TEMPLATE = """
import json

MARKER = {marker!r}

def lambda_handler(event, context):
    print(MARKER)
    return {{"statusCode": 200, "body": json.dumps({{"marker": MARKER}})}}
"""


def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _lambda_zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_function_with_retry(lambda_client, retries: int = 15, delay_s: float = 4.0, **kwargs):
    last_err = None
    for _ in range(retries):
        try:
            return lambda_client.create_function(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(delay_s)
    raise last_err


def _wait_lambda_active(lambda_client, function_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        state = lambda_client.get_function(FunctionName=function_name)["Configuration"]["State"]
        if state == "Active":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"Lambda function {function_name!r} never became Active, last state={state!r}")
        time.sleep(2)


def _reap_log_group(ctx, name: str) -> None:
    """delete_function does not remove /aws/lambda/<fn>, and a late log flush can recreate it
    after a single delete -- so reap in rounds and re-check, declaring a leak if it persists."""
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


def _delete_usage_plan(ag, usage_plan_id: str, api_stage: str) -> None:
    """DeleteUsagePlan refuses a plan that still has API stages, so remove the stage first; a plan
    that is already gone is done."""
    try:
        ag.update_usage_plan(
            usagePlanId=usage_plan_id,
            patchOperations=[{"op": "remove", "path": "/apiStages", "value": api_stage}],
        )
        ag.delete_usage_plan(usagePlanId=usage_plan_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_get(url: str, headers: dict, timeout_s: float, want_200: bool):
    deadline = time.monotonic() + timeout_s
    last_status, last_body = None, b""
    while True:
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                last_status, last_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            last_status, last_body = exc.code, exc.read()
        except urllib.error.URLError:
            last_status, last_body = None, b""
        if want_200 and last_status == 200:
            return last_status, last_body
        if not want_200 and last_status is not None and last_status != 200:
            return last_status, last_body
        if time.monotonic() >= deadline:
            return last_status, last_body
        time.sleep(3.0)


def _invocation_count(logs, log_group: str, marker: str, since_ms: int) -> int:
    try:
        resp = logs.filter_log_events(
            logGroupName=log_group, startTime=since_ms, filterPattern=f'"{marker}"'
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return 0
        raise
    return len(resp.get("events", []))


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An apiKeyRequired method answers an x-api-key matching no ApiKey with 403 and never invokes
    its AWS_PROXY backend Lambda (read from CloudWatch Logs); a valid usage-plan key invokes it."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    ag = ctx.client("apigateway")
    logs = ctx.client("logs")

    role_name = ctx.unique_name("sim2real-behav-role-apikeyguard-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "apigw-apikeyrequired-guard"}],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            }],
        }),
    )

    def _delete_role():
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

    ctx.on_cleanup(_delete_role)

    marker = f"sim2real-backend-invoked-{uuid.uuid4().hex[:12]}"
    backend_fn_name = ctx.unique_name("sim2real-behav-fn-apikeyguard-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, backend_fn_name))
    backend_arn = _create_function_with_retry(
        lam,
        FunctionName=backend_fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": _lambda_zip("lambda_function.py", _BACKEND_CODE_TEMPLATE.format(marker=marker))},
        Timeout=10,
        Tags={"sim2real": "apigw-apikeyrequired-guard"},
    )["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=backend_fn_name))
    _wait_lambda_active(lam, backend_fn_name)
    log_group = f"/aws/lambda/{backend_fn_name}"

    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-apikeyguard-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))

    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="guarded")["id"]
    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        apiKeyRequired=True,
    )
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{backend_arn}/invocations",
    )
    lam.add_permission(
        FunctionName=backend_fn_name,
        StatementId="sim2real-apigw-invoke-backend",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )

    stage_name = "prod"
    ag.create_deployment(restApiId=api_id, stageName=stage_name)

    usage_plan_id = ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-up-apikeyguard-"),
        apiStages=[{"apiId": api_id, "stage": stage_name}],
    )["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan(ag, usage_plan_id, f"{api_id}:{stage_name}"))

    created_key = ag.create_api_key(name=ctx.unique_name("sim2real-behav-key-apikeyguard-"), enabled=True)
    key_id, key_value = created_key["id"], created_key["value"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=key_id))
    ag.create_usage_plan_key(usagePlanId=usage_plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: ag.delete_usage_plan_key(usagePlanId=usage_plan_id, keyId=key_id))

    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/guarded"

    # Break exactly one thing: send a key that matches no provisioned ApiKey at all.
    since_ms = int(time.time() * 1000)
    denied_status, denied_body = _poll_get(
        invoke_url, {"x-api-key": "sim2real-no-such-key"}, timeout_s=90.0, want_200=False
    )
    assert denied_status == 403, (
        f"expected 403 Forbidden for a mismatched x-api-key, got {denied_status}: {denied_body[:300]!r}"
    )
    assert json.loads(denied_body) == {"message": "Forbidden"}, (
        f'expected the opaque body {{"message": "Forbidden"}} for a mismatched x-api-key, got {denied_body[:300]!r}'
    )

    deadline = time.monotonic() + 45.0
    seen = _invocation_count(logs, log_group, marker, since_ms)
    while seen == 0 and time.monotonic() < deadline:
        time.sleep(5.0)
        seen = _invocation_count(logs, log_group, marker, since_ms)
    assert seen == 0, (
        f"backend Lambda {backend_fn_name!r} was invoked {seen} time(s) despite a mismatched "
        "x-api-key -- apiKeyRequired was enforced only at the response layer, not before the "
        "AWS_PROXY integration ran"
    )

    # Control: a valid key's invocation is seen in the logs, so the absence above is meaningful.
    since_ms_valid = int(time.time() * 1000)
    allowed_status, allowed_body = _poll_get(
        invoke_url, {"x-api-key": key_value}, timeout_s=90.0, want_200=True
    )
    assert allowed_status == 200, (
        f"expected 200 with a valid usage-plan key, got {allowed_status}: {allowed_body[:300]!r}"
    )
    assert json.loads(allowed_body).get("marker") == marker, (
        f"backend response did not carry the expected marker: {allowed_body[:300]!r}"
    )
    deadline = time.monotonic() + 45.0
    seen_allowed = _invocation_count(logs, log_group, marker, since_ms_valid)
    while seen_allowed == 0 and time.monotonic() < deadline:
        time.sleep(5.0)
        seen_allowed = _invocation_count(logs, log_group, marker, since_ms_valid)
    assert seen_allowed >= 1, (
        "positive control failed: a VALID key left no invocation log line, so the log-based "
        "absence check above cannot be trusted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

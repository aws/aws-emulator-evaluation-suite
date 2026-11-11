"""apigw-http-api-access-logs-json-format."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-http-api-access-logs-json-format"
GROUP = "data-format"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_LAMBDA_CODE = """
import json

def handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"ok": True})}
"""

_LOG_FORMAT = (
    '{"requestId":"$context.requestId","ip":"$context.identity.sourceIp",'
    '"httpMethod":"$context.httpMethod","resourcePath":"$context.resourcePath",'
    '"status":"$context.status"}'
)

_PUSH_LOGS_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "dp:endpoint", "plane:data", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """A REST API stage with a JSON-format AccessLogSetting delivers structured JSON access-log
    entries (parseable, with the expected fields) to CloudWatch Logs after real traffic."""
    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-xsvc-apigw-access-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}"

    _ensure_account_cloudwatch_role(ctx)

    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-restapi-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="ping")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    uri = f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn['arn']}/invocations"
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=uri,
    )
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/*/*",
    )
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    apigw.update_stage(
        restApiId=api_id,
        stageName="prod",
        patchOperations=[
            {"op": "replace", "path": "/accessLogSettings/destinationArn", "value": log_group_arn},
            {"op": "replace", "path": "/accessLogSettings/format", "value": _LOG_FORMAT},
        ],
    )

    url = f"{ctx.rest_api_url(api_id, 'prod')}/ping"
    _poll_http_get(url, timeout_s=60)

    record = _poll_for_json_access_log(ctx, log_group_name, url=url, timeout_s=150)
    assert record["httpMethod"] == "GET", f"expected httpMethod GET, got {record['httpMethod']!r}"
    assert record["resourcePath"] == "/ping", f"expected resourcePath /ping, got {record['resourcePath']!r}"
    assert record["status"] == "200", f"expected status 200, got {record['status']!r}"
    assert record["requestId"], f"expected a non-empty requestId, got {record['requestId']!r}"
    assert record["ip"], f"expected a non-empty source ip, got {record['ip']!r}"


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lamrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_lambda_function(ctx, role_arn, code, handler="index.handler", timeout=10) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    zip_bytes = buf.getvalue()

    last_err = None
    resp = None
    for _ in range(10):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))

    deadline = time.monotonic() + 45
    state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            break
        time.sleep(2)
    if state != "Active":
        raise AssertionError(f"lambda function {name} never became Active (last state={state})")

    return {"name": name, "arn": resp["FunctionArn"]}


def _ensure_account_cloudwatch_role(ctx) -> None:
    """REST API access logging requires the account-level cloudWatchRoleArn. Point it at a role
    this check creates, and restore the account's original value on cleanup."""
    apigw = ctx.client("apigateway")
    iam = ctx.client("iam")
    original_role_arn = apigw.get_account().get("cloudwatchRoleArn") or ""

    role_name = ctx.unique_name("sim2real-apigwcw-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_PUSH_LOGS_POLICY_ARN)

    def _delete_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_PUSH_LOGS_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    def _restore():
        apigw.update_account(
            patchOperations=[
                {"op": "replace", "path": "/cloudwatchRoleArn", "value": original_role_arn}
            ]
        )

    # LIFO: the account setting is put back before the role it points at is deleted.
    ctx.on_cleanup(_delete_role)
    ctx.on_cleanup(_restore)

    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(patchOperations=[{"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}])
            break
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "BadRequestException":
                raise
            last_exc = e
            time.sleep(5)
    else:
        raise AssertionError(f"apigateway account never accepted the new cloudwatchRoleArn: {last_exc}")

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if apigw.get_account().get("cloudwatchRoleArn") == role_arn:
            break
        time.sleep(3)
    # IAM role/policy propagation before API Gateway can actually assume it to write logs is not
    # independently observable here; the downstream bounded poll for a delivered access-log entry
    # (up to 150s, regenerating traffic) is what actually absorbs that delay.


def _http_hit(url, timeout_s=10.0) -> int | None:
    """One traffic-generating GET; the HTTP status, or None when the host was unreachable."""
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


def _poll_http_get(url, timeout_s=60.0, interval_s=3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                if resp.status == 200:
                    return resp.read().decode()
                last_exc = AssertionError(f"unexpected status {resp.status}")
        except urllib.error.HTTPError as e:
            last_exc = e
        except urllib.error.URLError as e:
            last_exc = e
        time.sleep(interval_s)
    raise AssertionError(f"endpoint never returned 200 within {timeout_s}s: {last_exc}")


def _poll_for_json_access_log(ctx, log_group_name, url=None, timeout_s=150.0, interval_s=5.0) -> dict:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    start_time = int((time.time() - 300) * 1000)
    last_ping = 0.0
    raw_seen: list[str] = []
    while time.monotonic() < deadline:
        # Access-log delivery is asynchronous; keep generating fresh traffic while we wait so a
        # late-arriving delivery pipeline still has requests to log.
        if url is not None and time.monotonic() - last_ping > 20:
            _http_hit(url)
            last_ping = time.monotonic()
        try:
            resp = logs.filter_log_events(logGroupName=log_group_name, startTime=start_time)
            events = resp.get("events", [])
        except logs.exceptions.ResourceNotFoundException:
            events = []
        for event in events:
            message = event.get("message", "")
            if message not in raw_seen:
                raw_seen.append(message)
            try:
                parsed = json.loads(message)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(parsed, dict) and "requestId" in parsed:
                return parsed
        time.sleep(interval_s)
    raise AssertionError(
        f"no JSON access-log entry landed in {log_group_name} within {timeout_s}s; "
        f"raw_events_seen={raw_seen[:5]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


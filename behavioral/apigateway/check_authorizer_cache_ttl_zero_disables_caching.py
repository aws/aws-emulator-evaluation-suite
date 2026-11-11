"""authorizer-cache-ttl-zero-disables-caching."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "authorizer-cache-ttl-zero-disables-caching"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """authorizerResultTtlInSeconds=0 forces the Lambda authorizer to be re-invoked on every
    request through the deployed stage that sends the same Authorization token, rather than
    reusing a cached authorization result."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    logs = ctx.client("logs")

    account_id = sts.get_caller_identity()["Account"]

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-authttl-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_name = ctx.unique_name("sim2real-authttl-role-")
    assume_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=assume_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-authttl-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    handler_src = (
        "import boto3, os\n"
        "def handler(event, context):\n"
        "    boto3.client('sqs').send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody='invoked')\n"
        "    return {\n"
        "        'principalId': 'sim2real-user',\n"
        "        'policyDocument': {\n"
        "            'Version': '2012-10-17',\n"
        "            'Statement': [{'Action': 'execute-api:Invoke', 'Effect': 'Allow', "
        "'Resource': event['methodArn']}],\n"
        "        },\n"
        "    }\n"
    )
    zip_bytes = _zip_python_source(handler_src, "index.py")

    function_name = ctx.unique_name("sim2real-authttl-fn-")
    deadline = time.monotonic() + 60.0
    lambda_arn = None
    while lambda_arn is None:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            lambda_arn = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Environment={"Variables": {"QUEUE_URL": queue_url}},
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    lam.get_waiter("function_active").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-authttl-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authttl-authorizer-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{lambda_arn}/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]

    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=(
            f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{authorizer_id}"
        ),
    )

    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    apigw.create_deployment(restApiId=api_id, stageName="test")
    url = ctx.rest_api_url(api_id, "test")
    headers = {"Authorization": "Bearer sim2real-token"}

    warm_status = _wait_http_ok(url, headers, timeout_s=90.0, interval_s=3.0)
    assert warm_status == 200, f"stage did not become callable with the token, last HTTP {warm_status}"
    _drain_queue_count(sqs, queue_url, expected=1000, timeout_s=10.0)

    num_calls = 3
    start_time_ms = int(time.time() * 1000)
    for i in range(num_calls):
        status, body = _http_get(url, headers)
        assert status == 200, f"call {i}: expected HTTP 200 through the stage, got {status}; body={body!r}"

    log_invocations = _wait_for_report_count(
        logs, f"/aws/lambda/{function_name}", start_time_ms, expected=num_calls, timeout_s=60.0
    )

    invoked = _drain_queue_count(sqs, queue_url, expected=num_calls, timeout_s=60.0)
    assert invoked == num_calls, (
        f"expected exactly {num_calls} fresh authorizer invocations with ttl=0, saw {invoked} via "
        f"SQS side-channel and {log_invocations} via CloudWatch Logs REPORT lines"
    )



def _zip_python_source(source: str, filename: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _http_get(url: str, headers: dict[str, str], timeout: float = 15.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def _wait_http_ok(url: str, headers: dict[str, str], timeout_s: float, interval_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    status = -1
    while time.monotonic() < deadline:
        status, _body = _http_get(url, headers)
        if status == 200:
            return status
        time.sleep(interval_s)
    return status


def _drain_queue_count(sqs, queue_url: str, expected: int, timeout_s: float) -> int:
    count = 0
    deadline = time.monotonic() + timeout_s
    while count < expected and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            count += 1
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return count


def _wait_for_report_count(
    logs, log_group: str, start_time_ms: int, expected: int, timeout_s: float, interval_s: float = 5.0
) -> int:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    count = 0
    while time.monotonic() < deadline:
        try:
            events = logs.filter_log_events(
                logGroupName=log_group, startTime=start_time_ms, filterPattern='"REPORT RequestId"'
            )["events"]
            count = len(events)
            if count >= expected:
                return count
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    return count


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

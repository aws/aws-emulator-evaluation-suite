"""cognito-post-confirmation-trigger-invokes-lambda."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cognito-post-confirmation-trigger-invokes-lambda"
GROUP = "trigger-delivery"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PostConfirmation Lambda trigger is invoked synchronously with the confirmed
    user's attributes right after AdminConfirmSignUp completes the sign-up."""
    queue_url = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    code = (
        "import json, os, boto3\n"
        "sqs = boto3.client('sqs')\n"
        "def handler(event, context):\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps({\n"
        "        'triggerSource': event.get('triggerSource'),\n"
        "        'userName': event.get('userName'),\n"
        "        'userPoolId': event.get('userPoolId'),\n"
        "        'email': event.get('request', {}).get('userAttributes', {}).get('email'),\n"
        "    }))\n"
        "    return event\n"
    )
    fn_name, fn_arn = _create_lambda_function(
        ctx, role_arn, code, env={"QUEUE_URL": queue_url}
    )
    pool_id, pool_arn = _create_user_pool(
        ctx, lambda_config={"PostConfirmation": fn_arn}
    )
    _grant_cognito_invoke(ctx, fn_name, pool_arn)
    client_id = _create_pool_client(ctx, pool_id)

    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    email = f"{username}@example.com"
    idp.sign_up(
        ClientId=client_id,
        Username=username,
        Password="Sim2Real!Passw0rd",
        UserAttributes=[{"Name": "email", "Value": email}],
    )
    idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)

    payload = _wait_for_message(ctx, queue_url, timeout_s=90.0)
    assert payload["triggerSource"] == "PostConfirmation_ConfirmSignUp", (
        f"expected triggerSource 'PostConfirmation_ConfirmSignUp', got {payload['triggerSource']!r}"
    )
    assert payload["userName"] == username, (
        f"expected userName {username!r}, got {payload['userName']!r}"
    )
    assert payload["userPoolId"] == pool_id, (
        f"expected userPoolId {pool_id!r}, got {payload['userPoolId']!r}"
    )
    assert payload["email"] == email, (
        f"expected email {email!r}, got {payload['email']!r}"
    )


# ===== helpers =====


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _zip_code(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cog-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send")
    )
    return role_arn


def _create_lambda_function(
    ctx, role_arn: str, code: str, env: dict[str, str] | None = None
) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cog-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_code(code)},
        Timeout=15,
        Publish=True,
        Tags={"sim2real:managed": "true"},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    fn_arn = None
    last_err: Exception | None = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            fn_arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    if fn_arn is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} Active",
    )
    return name, fn_arn


def _grant_cognito_invoke(ctx, function_name: str, source_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="cognito-invoke",
        Action="lambda:InvokeFunction",
        Principal="cognito-idp.amazonaws.com",
        SourceArn=source_arn,
    )


def _create_user_pool(
    ctx, lambda_config: dict[str, Any] | None = None, **extra
) -> tuple[str, str]:
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-cog-pool-")
    kwargs: dict[str, Any] = {
        "PoolName": name,
        "UserPoolTags": {"sim2real:managed": "true"},
        # AWS now defaults new user pools to DeletionProtection=ACTIVE, which makes the plain
        # DeleteUserPool cleanup below fail and leak the
        # pool. This check does not exercise deletion protection, so opt out of it explicitly.
        "DeletionProtection": "INACTIVE",
    }
    if lambda_config:
        kwargs["LambdaConfig"] = lambda_config
    kwargs.update(extra)
    pool = idp.create_user_pool(**kwargs)["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: _delete_user_pool_retrying(idp, pool_id))
    return pool_id, pool["Arn"]


def _delete_user_pool_retrying(idp, pool_id: str) -> None:
    """Teardown: a pool already gone is clean; a concurrent change or throttle is retried every 2 s
    to 30 s; any other failure raises."""
    deadline = time.monotonic() + 30.0
    while True:
        try:
            idp.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in {"ConcurrentModificationException", "TooManyRequestsException"} \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_pool_client(
    ctx, pool_id: str, explicit_auth_flows: list[str] | None = None
) -> str:
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-cog-client-")
    flows = explicit_auth_flows or [
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_CUSTOM_AUTH",
    ]
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=name,
        ExplicitAuthFlows=flows,
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )
    return client_id


def _create_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cog-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _wait_for_message(ctx, queue_url: str, timeout_s: float = 90.0) -> dict[str, Any]:
    sqs = ctx.client("sqs")

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return json.loads(msgs[0]["Body"])
        return None

    return _poll_until(
        probe,
        lambda v: v is not None,
        timeout_s=timeout_s,
        interval_s=3.0,
        description="SQS trigger message",
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

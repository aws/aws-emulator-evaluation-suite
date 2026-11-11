"""cognito-define-auth-challenge-trigger-chain."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cognito-define-auth-challenge-trigger-chain"
GROUP = "trigger-delivery"
SERVICES = ["apigateway", "cognito-idp", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CUSTOM_AUTH flow invokes its triggers in order Define, Create, Verify, Define.
    The correct answer issues tokens, and the access token authenticates the user via GetUser."""
    queue_url = _create_fifo_queue(ctx)
    role_arn = _create_lambda_role(ctx)

    define_code = (
        "import json, os, boto3\n"
        "sqs = boto3.client('sqs')\n"
        "def handler(event, context):\n"
        "    session = event['request']['session']\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageGroupId='chain',\n"
        "        MessageDeduplicationId=context.aws_request_id,\n"
        "        MessageBody=json.dumps({'trigger': 'Define', 'sessionLen': len(session)}))\n"
        "    if len(session) == 0:\n"
        "        event['response']['challengeName'] = 'CUSTOM_CHALLENGE'\n"
        "        event['response']['issueTokens'] = False\n"
        "        event['response']['failAuthentication'] = False\n"
        "    elif session[-1].get('challengeResult') is True:\n"
        "        event['response']['issueTokens'] = True\n"
        "        event['response']['failAuthentication'] = False\n"
        "    else:\n"
        "        event['response']['issueTokens'] = False\n"
        "        event['response']['failAuthentication'] = True\n"
        "    return event\n"
    )
    create_code = (
        "import json, os, boto3\n"
        "sqs = boto3.client('sqs')\n"
        "def handler(event, context):\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageGroupId='chain',\n"
        "        MessageDeduplicationId=context.aws_request_id,\n"
        "        MessageBody=json.dumps({'trigger': 'Create'}))\n"
        "    event['response']['publicChallengeParameters'] = {'question': 'what-is-sim2real'}\n"
        "    event['response']['privateChallengeParameters'] = {'answer': 'sim2real-42'}\n"
        "    event['response']['challengeMetadata'] = 'CUSTOM_CHALLENGE'\n"
        "    return event\n"
    )
    verify_code = (
        "import json, os, boto3\n"
        "sqs = boto3.client('sqs')\n"
        "def handler(event, context):\n"
        "    expected = event['request']['privateChallengeParameters']['answer']\n"
        "    provided = event['request']['challengeAnswer']\n"
        "    correct = provided == expected\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageGroupId='chain',\n"
        "        MessageDeduplicationId=context.aws_request_id,\n"
        "        MessageBody=json.dumps({'trigger': 'Verify', 'correct': correct}))\n"
        "    event['response']['answerCorrect'] = correct\n"
        "    return event\n"
    )

    env = {"QUEUE_URL": queue_url}
    define_name, define_arn = _create_lambda_function(ctx, role_arn, define_code, env)
    create_name, create_arn = _create_lambda_function(ctx, role_arn, create_code, env)
    verify_name, verify_arn = _create_lambda_function(ctx, role_arn, verify_code, env)

    pool_id, pool_arn = _create_user_pool(
        ctx,
        lambda_config={
            "DefineAuthChallenge": define_arn,
            "CreateAuthChallenge": create_arn,
            "VerifyAuthChallengeResponse": verify_arn,
        },
    )
    _grant_cognito_invoke(ctx, define_name, pool_arn)
    _grant_cognito_invoke(ctx, create_name, pool_arn)
    _grant_cognito_invoke(ctx, verify_name, pool_arn)
    client_id = _create_pool_client(
        ctx,
        pool_id,
        explicit_auth_flows=["ALLOW_CUSTOM_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"],
    )

    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id,
        Username=username,
        Password="Sim2Real!Passw0rd",
        Permanent=True,
    )

    start = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="CUSTOM_AUTH",
        AuthParameters={"USERNAME": username},
    )
    assert start["ChallengeName"] == "CUSTOM_CHALLENGE", (
        f"expected the Define trigger to drive a custom challenge, got {start['ChallengeName']!r}"
    )
    assert start["ChallengeParameters"]["question"] == "what-is-sim2real", (
        "expected the Create trigger's public parameter to reach the client, got "
        f"{start['ChallengeParameters']!r}"
    )

    finish = idp.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="CUSTOM_CHALLENGE",
        ChallengeResponses={"USERNAME": username, "ANSWER": "sim2real-42"},
        Session=start["Session"],
    )
    assert "AuthenticationResult" in finish, (
        f"expected the correct answer to issue tokens, got {sorted(finish)!r}"
    )
    access_token = finish["AuthenticationResult"]["AccessToken"]
    assert access_token, f"expected a non-empty AccessToken, got {access_token!r}"

    # The minted token must be usable, not just present.
    who = idp.get_user(AccessToken=access_token)
    assert who["Username"] == username, (
        f"expected the minted token to authenticate {username!r}, got {who['Username']!r}"
    )

    messages = _drain_messages(ctx, queue_url, expected_min=4, timeout_s=90.0)
    order = [m["trigger"] for m in messages[:4]]
    expected_order = ["Define", "Create", "Verify", "Define"]
    assert order == expected_order, (
        f"expected trigger invocation order {expected_order}, got {order}"
    )
    assert messages[2]["correct"] is True, (
        f"expected the Verify trigger to report the answer correct, got {messages[2]!r}"
    )


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
    # IAM propagation lag is absorbed by the create_function retry in _create_lambda_function.
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
    kwargs: dict[str, Any] = {"PoolName": name}
    if lambda_config:
        kwargs["LambdaConfig"] = lambda_config
    kwargs.update(extra)
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true"})
    pool = idp.create_user_pool(**kwargs)["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id, pool["Arn"]


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


def _create_fifo_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-cog-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _drain_messages(
    ctx, queue_url: str, expected_min: int, timeout_s: float = 90.0
) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_min and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    if len(out) < expected_min:
        raise AssertionError(
            f"expected >= {expected_min} chain messages, got {len(out)}: {out}"
        )
    return out


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

"""iam-role-wrong-principal-sns-trust-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-wrong-principal-sns-trust-rejected"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:rejection", "cap:c7", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetTopicAttributes rejects a delivery-status feedback role that does not trust
    sns.amazonaws.com with InvalidParameter and its exact message; a correctly trusted role is
    accepted and produces delivery-status logs."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    sns = ctx.client("sns")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    account_id = sts.get_caller_identity()["Account"]

    # SNS requires the CALLER (not the target role) to hold iam:PassRole for any role
    # named in a *FeedbackRoleArn attribute, scoped by PassedToService=sns.amazonaws.com.
    # The caller's own identity may lack that grant -- SetTopicAttributes would then
    # fail synchronously with AuthorizationError on iam:PassRole before ever reaching the
    # trust-policy question this check is about. Route those specific calls through a
    # purpose-built role that DOES hold the PassRole grant, so the only variable
    # left is the target role's own trust document.
    sns_broker = _sns_client_with_pass_role(ctx, iam, sts)

    fn_name, fn_arn = _create_subscriber_function(ctx, iam, lam)

    topic_name = ctx.unique_name("sim2real-behav-pb-topic-")
    topic_arn = sns.create_topic(Name=topic_name, Tags=[{"Key": "sim2real", "Value": topic_name}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sns-invoke",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic_arn,
    )
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=fn_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    log_group = f"sns/{ctx.region}/{account_id}/{topic_name}"
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(logs, log_group))

    bad_role_name = ctx.unique_name("sim2real-behav-pb-bad-srole-")
    bad_role_arn = _create_feedback_role(ctx, iam, bad_role_name, "s3.amazonaws.com")

    message = _expect_invalid_role_rejection(sns_broker, topic_arn, "LambdaSuccessFeedbackRoleArn", bad_role_arn)
    expected_message = (
        f"Invalid parameter: LambdaSuccessFeedbackRoleArn: {bad_role_arn} "
        "is not a valid role to allow SNS to write to Cloudwatch Logs"
    )
    assert message == expected_message, (
        f"SetTopicAttributes rejected the wrongly-trusted feedback role with InvalidParameter, "
        f"expected message {expected_message!r}, got {message!r}"
    )

    good_role_name = ctx.unique_name("sim2real-behav-pb-good-srole-")
    good_role_arn = _create_feedback_role(ctx, iam, good_role_name, "sns.amazonaws.com")
    _set_topic_attr_with_retry(sns_broker, topic_arn, "LambdaSuccessFeedbackRoleArn", good_role_arn)
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="LambdaSuccessFeedbackSampleRate", AttributeValue="100")
    _set_topic_attr_with_retry(sns_broker, topic_arn, "LambdaFailureFeedbackRoleArn", good_role_arn)

    sns.publish(TopicArn=topic_arn, Message="correct-trust-probe")
    seen_good = _poll_for_log_events(logs, log_group, timeout_s=150.0)
    assert seen_good, "positive control: the correctly-trusted feedback role never produced delivery status log entries"


def _sns_client_with_pass_role(ctx: Any, iam: Any, sts: Any) -> Any:
    """An SNS client backed by a dedicated role that holds iam:PassRole scoped to
    PassedToService=sns.amazonaws.com. Without that grant on the caller, SetTopicAttributes
    on a *FeedbackRoleArn attribute fails synchronously on the CALLER's own PassRole
    permission -- before AWS ever looks at the target role's trust document. Using this
    role isolates the trust-policy question the check is actually about."""
    account_id = sts.get_caller_identity()["Account"]
    broker_name = ctx.unique_name("sim2real-behav-pb-broker-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    broker_arn = iam.create_role(
        RoleName=broker_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": broker_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=broker_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "sns.amazonaws.com"}},
            },
            {"Effect": "Allow", "Action": "sns:SetTopicAttributes", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=broker_name, PolicyName="pass-role-sns", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=broker_name, PolicyName="pass-role-sns"))

    deadline = time.monotonic() + 90.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=broker_arn, RoleSessionName="sns-pass-role-probe")["Credentials"]
            return ctx.client(
                "sns",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except Exception as exc:  # role/policy propagation delay
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"could not assume PassRole broker role (propagation?): {last_exc}")


def _expect_invalid_role_rejection(sns_broker: Any, topic_arn: str, attr_name: str, bad_role_arn: str, timeout_s: float = 60.0) -> str:
    """Return the error message of the InvalidParameter rejection SetTopicAttributes gives
    the badly-trusted role. An acceptance raises. Retries only past the broker's own
    transient AuthorizationError (its PassRole/SetTopicAttributes grant still propagating)
    -- an InvalidParameter naming the role is the actual signal."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sns_broker.set_topic_attributes(TopicArn=topic_arn, AttributeName=attr_name, AttributeValue=bad_role_arn)
        except sns_broker.exceptions.AuthorizationErrorException as exc:
            last_exc = exc
            time.sleep(5)
            continue
        except sns_broker.exceptions.InvalidParameterException as exc:
            return exc.response["Error"]["Message"]
        raise AssertionError(
            "SetTopicAttributes accepted a feedback role whose trust policy does not "
            "name sns.amazonaws.com -- the wrongly-trusted role was not rejected"
        )
    raise AssertionError(f"SetTopicAttributes({attr_name}) via broker never authorized (propagation?): {last_exc}")


def _set_topic_attr_with_retry(sns_broker: Any, topic_arn: str, attr_name: str, attr_value: str, timeout_s: float = 60.0) -> None:
    """The broker's own PassRole/SetTopicAttributes permission can still be propagating
    for a few seconds right after AssumeRole succeeds; retry on AuthorizationError rather
    than treating that race as the trust-policy signal this check is measuring."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sns_broker.set_topic_attributes(TopicArn=topic_arn, AttributeName=attr_name, AttributeValue=attr_value)
            return
        except sns_broker.exceptions.AuthorizationErrorException as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"SetTopicAttributes({attr_name}) via broker never authorized (propagation?): {last_exc}")


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_function_with_retry(lam: Any, fn_name: str, role_arn: str, zip_bytes: bytes, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
                Tags={"sim2real": fn_name},
            )["FunctionArn"]
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"CreateFunction never succeeded (role propagation?): {last_exc}")


def _wait_for_active(lam: Any, fn_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name)["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError("function entered Failed state")
        time.sleep(3)
    raise AssertionError("function never reached Active state")


def _create_subscriber_function(ctx: Any, iam: Any, lam: Any) -> tuple[str, str]:
    role_name = ctx.unique_name("sim2real-behav-pb-subrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))

    fn_name = ctx.unique_name("sim2real-behav-pb-subfn-")
    zip_bytes = _lambda_zip("def handler(event, context):\n    return {'ok': True}\n")
    fn_arn = _create_function_with_retry(lam, fn_name, role_arn, zip_bytes, timeout_s=90.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_for_active(lam, fn_name, timeout_s=90.0)
    return fn_name, fn_arn


def _create_feedback_role(ctx: Any, iam: Any, role_name: str, trust_service: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))
    return role_arn


def _delete_log_group_if_exists(logs: Any, log_group: str) -> None:
    try:
        logs.delete_log_group(logGroupName=log_group)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _poll_for_log_events(logs: Any, log_group: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            groups = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
        except logs.exceptions.ResourceNotFoundException:
            groups = []
        if any(g["logGroupName"] == log_group for g in groups):
            try:
                resp = logs.filter_log_events(logGroupName=log_group)
                if resp.get("events"):
                    return True
            except logs.exceptions.ResourceNotFoundException:
                pass
        time.sleep(2)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

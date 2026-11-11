"""iam-role-trusts-sns-service-assumed."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trusts-sns-service-assumed"
GROUP = "trust-policy"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """SNS assumes a feedback role trusting sns.amazonaws.com: after a publish, a delivery-status log
    naming the Lambda endpoint with status SUCCESS appears in sns/<region>/<account>/<topic>."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    sns = ctx.client("sns")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-tp-srole-")
    role_arn = _create_feedback_role(ctx, iam, role_name, "sns.amazonaws.com")

    fn_name, fn_arn = _create_subscriber_function(ctx, iam, lam)

    topic_name = ctx.unique_name("sim2real-behav-tp-topic-")
    topic_arn = sns.create_topic(Name=topic_name, Tags=_tags_kv())["TopicArn"]
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

    # SNS test-assumes the feedback role at SetTopicAttributes time, and a new IAM role is not
    # instantly visible to every service; retry the transient AuthorizationError.
    _set_feedback_attr_with_retry(sns, topic_arn, "LambdaSuccessFeedbackRoleArn", role_arn)
    _set_feedback_attr_with_retry(sns, topic_arn, "LambdaSuccessFeedbackSampleRate", "100")
    _set_feedback_attr_with_retry(sns, topic_arn, "LambdaFailureFeedbackRoleArn", role_arn)

    log_group = f"sns/{ctx.region}/{account_id}/{topic_name}"
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(logs, log_group))

    sns.publish(TopicArn=topic_arn, Message="trust-policy-probe")

    events = _poll_for_log_events(logs, log_group, timeout_s=180.0)
    if not events:
        raise AssertionError(
            f"delivery status log never appeared in {log_group} within the 180s poll budget -- "
            "SNS feedback-logging latency exceeded the budget on this run; this is the CloudWatch "
            "telemetry-latency escape hatch, not a pass -- widen the budget if this recurs",
        )
    # Any entry in the group is not enough: the delivery-status record must name the endpoint
    # and report success.
    joined = " ".join(e["message"] for e in events)
    if fn_arn not in joined or '"status":"SUCCESS"' not in joined.replace(" ", ""):
        raise AssertionError(
            f"delivery-status log in {log_group} does not name {fn_arn} with status SUCCESS: {joined[:300]!r}"
        )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav-tp"}]


def _set_feedback_attr_with_retry(sns: Any, topic_arn: str, attr_name: str, attr_value: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            sns.set_topic_attributes(TopicArn=topic_arn, AttributeName=attr_name, AttributeValue=attr_value)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AuthorizationError":
                raise
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"SetTopicAttributes({attr_name}) never succeeded (role propagation?): {last_exc}")


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
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-tp"},
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
    role_name = ctx.unique_name("sim2real-behav-tp-subrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv())["Role"]["Arn"]
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

    fn_name = ctx.unique_name("sim2real-behav-tp-subfn-")
    # Registered first so it runs after delete_function (LIFO): the group Lambda creates on
    # first invocation outlives the function itself if not swept up here too.
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx.client("logs"), f"/aws/lambda/{fn_name}"))
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv())["Role"]["Arn"]
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


def _poll_for_log_events(logs: Any, log_group: str, timeout_s: float) -> list[dict]:
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
                    return resp["events"]
            except logs.exceptions.ResourceNotFoundException:
                pass
        time.sleep(2)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

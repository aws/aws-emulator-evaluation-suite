"""lambda-feedback-roles-log-the-invocation-delivery-record-and-the-uninvokable-function-failure."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-feedback-roles-log-the-invocation-delivery-record-and-the-uninvokable-function-failure"
GROUP = "delivery-status-logging"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c4", "concern:metrics", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda delivery feedback logs a SUCCESS/202 record for an invokable function and a
    FAILURE/403 AccessDeniedException record for one SNS may not invoke; only the invoked
    function creates its own /aws/lambda log group.
    """
    sns = ctx.client("sns")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    feedback_role = _create_feedback_role(ctx, iam, "sim2real-behav-sns-lfbrole-")
    fn_role = _create_lambda_exec_role(ctx, iam, "sim2real-behav-sns-lfbfnrole-")
    allowed_fn = _create_function(ctx, lam, fn_role, "sim2real-behav-sns-lfbok-")
    denied_fn = _create_function(ctx, lam, fn_role, "sim2real-behav-sns-lfbdeny-")

    topic_name = ctx.unique_name("sim2real-behav-sns-lfblog-")
    topic = sns.create_topic(Name=topic_name, Attributes={
        "LambdaSuccessFeedbackRoleArn": feedback_role, "LambdaSuccessFeedbackSampleRate": "100",
        "LambdaFailureFeedbackRoleArn": feedback_role},
        Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    success_log_group = f"sns/{ctx.region}/{ctx.account}/{topic_name}"
    failure_log_group = f"{success_log_group}/Failure"
    ctx.on_cleanup(lambda: _delete_log_group(logs, success_log_group))
    ctx.on_cleanup(lambda: _delete_log_group(logs, failure_log_group))

    allowed_arn = lam.get_function(FunctionName=allowed_fn)["Configuration"]["FunctionArn"]
    lam.add_permission(FunctionName=allowed_fn, StatementId="sns", Action="lambda:InvokeFunction",
                       Principal="sns.amazonaws.com", SourceArn=topic)
    sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=allowed_arn)

    denied_arn = lam.get_function(FunctionName=denied_fn)["Configuration"]["FunctionArn"]
    # Deliberately no add_permission: SNS cannot invoke this function.
    sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=denied_arn)

    mid = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-lfb-"))["MessageId"]

    successes = _poll_log_events(logs, success_log_group, mid, 120)
    matching_success = [r for r in successes if r["delivery"]["destination"] == allowed_arn]
    assert len(matching_success) == 1, (
        f"the success feedback log group must carry exactly one record for the invokable "
        f"function and MessageId {mid!r}; got {matching_success!r}")
    assert matching_success[0]["status"] == "SUCCESS" and matching_success[0]["delivery"]["statusCode"] == 202, (
        f"a successful Lambda delivery's record must be status SUCCESS with statusCode 202; "
        f"got {matching_success[0]!r}")
    provider = json.loads(matching_success[0]["delivery"]["providerResponse"])
    assert "lambdaRequestId" in provider, (
        f"a successful Lambda delivery's provider response must carry a lambdaRequestId; got {provider!r}")

    failures = _poll_log_events(logs, failure_log_group, mid, 120)
    matching_failure = [r for r in failures if r["delivery"]["destination"] == denied_arn]
    assert len(matching_failure) == 1, (
        f"the failure feedback log group must carry exactly one record for the denied function "
        f"and MessageId {mid!r}; got {matching_failure!r}")
    assert matching_failure[0]["status"] == "FAILURE" and matching_failure[0]["delivery"]["statusCode"] == 403, (
        f"the denied Lambda delivery's record must be status FAILURE with statusCode 403; "
        f"got {matching_failure[0]!r}")
    failure_provider = json.loads(matching_failure[0]["delivery"]["providerResponse"])
    assert failure_provider.get("ErrorCode") == "AccessDeniedException", (
        f"the denied delivery's provider response must name AccessDeniedException; got {failure_provider!r}")
    assert failure_provider.get("ErrorMessage") == (
        f"User: sns.amazonaws.com is not authorized to perform: lambda:InvokeFunction on resource: "
        f"{denied_arn} because no resource-based policy allows the lambda:InvokeFunction action"), (
        f"the provider response's ErrorMessage must name this exact denied function; got {failure_provider.get('ErrorMessage')!r}")

    # Both functions' execution role may write logs, so an invoked function creates its own
    # /aws/lambda/<fn> group, and its absence shows the denied function never ran.
    allowed_group = f"/aws/lambda/{allowed_fn}"
    deadline = time.monotonic() + 120
    while not _log_groups(logs, allowed_group):
        assert time.monotonic() < deadline, (
            f"the function SNS invoked never created its own log group {allowed_group!r}")
        time.sleep(5)

    lam.get_function(FunctionName=denied_fn)  # the function itself still exists
    own_groups = _log_groups(logs, f"/aws/lambda/{denied_fn}")
    assert own_groups == [], (
        f"a function SNS could not invoke must never create its own log group; found {own_groups!r}")


def _create_feedback_role(ctx, iam, prefix: str) -> str:
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))
    return role_arn


def _create_lambda_exec_role(ctx, iam, prefix: str) -> str:
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))
    # No sleep: create_function retries the not-yet-assumable role's InvalidParameterValueException.
    return role_arn


def _create_function(ctx, lam, role_arn: str, prefix: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", 'def handler(event, context):\n    return {"ok": True}\n')
    fn = ctx.unique_name(prefix)
    # Registered first so it runs after delete_function (LIFO): the group outlives its function.
    ctx.on_cleanup(lambda: _delete_log_group(ctx.client("logs"), f"/aws/lambda/{fn}"))
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": buf.getvalue()}, Timeout=10, Tags={"sim2real": CHECK})
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn


def _log_groups(logs, name: str) -> list[str]:
    """Names of the log groups that are exactly ``name`` (the prefix query, filtered)."""
    found = []
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        found.extend(g["logGroupName"] for g in page["logGroups"] if g["logGroupName"] == name)
    return found


def _delete_log_group(logs, log_group: str) -> None:
    try:
        logs.delete_log_group(logGroupName=log_group)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _poll_log_events(logs, log_group: str, message_id: str, timeout_s: float) -> list[dict]:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
            records = [json.loads(e["message"]) for e in resp.get("events", [])]
            matches = [r for r in records if r.get("notification", {}).get("messageId") == message_id]
            if matches or time.monotonic() >= deadline:
                return matches
        except logs.exceptions.ResourceNotFoundException:
            if time.monotonic() >= deadline:
                return []
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""eventbridge-lambda-invalidation-failure-routes-to-dlq."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-lambda-invalidation-failure-routes-to-dlq"
GROUP = "error-propagation"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A target DLQ receives EventBridge's own failed delivery (a missing invoke permission, with the rule ARN, target
    ARN and ERROR_CODE NO_PERMISSIONS) but never the event of a Lambda whose handler raises, which its logs show was
    invoked: EventBridge invokes Lambda asynchronously, so delivery completes before the handler runs."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-dlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    success_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-ok-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=success_url))
    success_arn = sqs.get_queue_attributes(QueueUrl=success_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    fail_role_arn = _create_lambda_role(ctx)
    fail_code = "def handler(event, context):\n    raise Exception('simulated CreateInvalidation failure')\n"
    fail_fn_name = ctx.unique_name("sim2real-fail-")
    fail_fn_arn = _create_lambda_function(ctx, fail_fn_name, fail_role_arn, fail_code)

    ok_role_arn = _create_lambda_role(
        ctx,
        inline_statements=[
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": success_arn}
        ],
    )
    ok_code = f"""
import json
import boto3
_sqs = boto3.client("sqs")
def handler(event, context):
    _sqs.send_message(QueueUrl={success_url!r}, MessageBody=json.dumps(event))
    return event
"""
    ok_fn_name = ctx.unique_name("sim2real-ok-")
    ok_fn_arn = _create_lambda_function(ctx, ok_fn_name, ok_role_arn, ok_code)
    _warm_up_role(ctx, ok_fn_name, success_url)

    marker_fail = ctx.unique_name("marker-fail-")
    marker_ok = ctx.unique_name("marker-ok-")
    marker_permfail = ctx.unique_name("marker-permfail-")

    rule_fail_name = ctx.unique_name("sim2real-rule-fail-")
    rule_fail_arn = events.put_rule(
        Name=rule_fail_name,
        EventPattern=json.dumps({"source": ["sim2real.cloudfront"], "detail": {"invalidationMarker": [marker_fail]}}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_fail_name))

    rule_ok_name = ctx.unique_name("sim2real-rule-ok-")
    rule_ok_arn = events.put_rule(
        Name=rule_ok_name,
        EventPattern=json.dumps({"source": ["sim2real.cloudfront"], "detail": {"invalidationMarker": [marker_ok]}}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_ok_name))

    # Twin control: an EventBridge-level delivery failure, not a target-code failure. Reuses
    # ok_fn as the target -- it is never actually invoked, since delivery itself is denied --
    # so no third Lambda function is needed to prove the DLQ path is live.
    rule_permfail_name = ctx.unique_name("sim2real-rule-permfail-")
    rule_permfail_arn = events.put_rule(
        Name=rule_permfail_name,
        EventPattern=json.dumps(
            {"source": ["sim2real.cloudfront"], "detail": {"invalidationMarker": [marker_permfail]}}
        ),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_permfail_name))

    _allow_eventbridge_invoke(ctx, fail_fn_name, rule_fail_arn, "AllowFail")
    _allow_eventbridge_invoke(ctx, ok_fn_name, rule_ok_arn, "AllowOk")
    # Deliberately do NOT grant rule_permfail_arn invoke permission on any function: the
    # invocation attempt itself is denied, which is the genuine EventBridge delivery failure.
    _grant_eventbridge_sqs(ctx, dlq_url, dlq_arn, [rule_fail_arn, rule_ok_arn, rule_permfail_arn])

    events.put_targets(
        Rule=rule_fail_name,
        Targets=[
            {
                "Id": "target-1",
                "Arn": fail_fn_arn,
                "DeadLetterConfig": {"Arn": dlq_arn},
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_fail_name, Ids=["target-1"]))

    events.put_targets(
        Rule=rule_ok_name,
        Targets=[
            {
                "Id": "target-1",
                "Arn": ok_fn_arn,
                "DeadLetterConfig": {"Arn": dlq_arn},
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_ok_name, Ids=["target-1"]))

    events.put_targets(
        Rule=rule_permfail_name,
        Targets=[
            {
                "Id": "target-1",
                "Arn": ok_fn_arn,
                "DeadLetterConfig": {"Arn": dlq_arn},
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_permfail_name, Ids=["target-1"]))

    t0 = time.monotonic()
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps({"eventName": "CreateInvalidation", "invalidationMarker": marker_ok}),
            },
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps({"eventName": "CreateInvalidation", "invalidationMarker": marker_fail}),
            },
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps({"eventName": "CreateInvalidation", "invalidationMarker": marker_permfail}),
            },
        ]
    )

    # Positive control: the succeeding target actually gets invoked and forwards the event.
    ok_msg = _poll_for_message(ctx, success_url, timeout_s=60)
    ok_body = json.loads(ok_msg["Body"])
    assert ok_body["detail"]["invalidationMarker"] == marker_ok

    # Independent side-channel: CloudWatch Logs proves the raising handler was actually
    # invoked (and did raise), so its absence from the DLQ below is a real absence rather
    # than "the target was never reached at all".
    _wait_for_log_message(ctx, logs, fail_fn_name, "simulated CreateInvalidation failure", timeout_s=60)

    # Twin control: the DLQ path itself is live, and this pins its latency L so the absence
    # check below waits long enough to be meaningful rather than trusting a bare sleep.
    permfail_buckets, elapsed_by_marker = _drain_and_bucket(ctx, dlq_url, timeout_s=30, t0=t0)
    assert permfail_buckets.get(marker_permfail), "expected the permission-denied control to land in the DLQ"
    assert not permfail_buckets.get(marker_fail), (
        f"the raising target's event reached the DLQ during the control wait: {permfail_buckets.get(marker_fail)}"
    )
    permfail_msg = permfail_buckets[marker_permfail][0]
    attrs = permfail_msg["MessageAttributes"]
    assert attrs["RULE_ARN"]["StringValue"] == rule_permfail_arn
    assert attrs["TARGET_ARN"]["StringValue"] == ok_fn_arn
    assert attrs["ERROR_CODE"]["StringValue"] == "NO_PERMISSIONS"
    latency_l = elapsed_by_marker[marker_permfail]

    # Main assertion: a target's own raised exception is invisible to the rule's DLQ. Hold
    # absence for >= 3x the just-measured delivery-failure latency (never a bare sleep), capped
    # so a freak large L cannot blow the suite budget.
    absence_window_s = min(max(3 * latency_l, 20.0), 60.0)
    remaining = absence_window_s - (time.monotonic() - t0)
    fail_buckets, _ = _drain_and_bucket(ctx, dlq_url, timeout_s=max(remaining, 1.0), t0=t0)
    assert not fail_buckets.get(marker_fail), (
        f"the raising target's event unexpectedly reached the DLQ: {fail_buckets.get(marker_fail)}"
    )


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-pol-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, name: str, role_arn: str, code: str) -> str:
    lam = ctx.client("lambda")
    zbytes = _zip_code(code)
    deadline = time.monotonic() + 30
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zbytes},
                Timeout=15,
                MemorySize=128,
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda creation never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_lambda_active(ctx, name)
    return resp["FunctionArn"]


def _wait_lambda_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda {name} never became Active")


def _allow_eventbridge_invoke(ctx, function_name: str, rule_arn: str, statement_id: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )


def _warm_up_role(ctx, fn_name: str, obs_queue_url: str, timeout_s: float = 60) -> None:
    """IAM role permissions attached just before function creation can lag behind
    for a few seconds; invoke directly (retrying on the function's own AccessDenied)
    until the role's sqs:SendMessage permission has propagated, then drain the
    warm-up message(s) so they don't contaminate the real assertions."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=fn_name, Payload=b'{"warmup": true}', InvocationType="RequestResponse")
        if resp.get("FunctionError"):
            last_err = resp["Payload"].read()
            time.sleep(3)
            continue
        break
    else:
        raise AssertionError(f"lambda role permissions never propagated: {last_err}")
    drain_deadline = time.monotonic() + 10
    while time.monotonic() < drain_deadline:
        r = sqs.receive_message(QueueUrl=obs_queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = r.get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            sqs.delete_message(QueueUrl=obs_queue_url, ReceiptHandle=m["ReceiptHandle"])


def _grant_eventbridge_sqs(ctx, queue_url: str, queue_arn: str, rule_arns: list[str], sid: str = "AllowEventBridge") -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arns}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _poll_for_message(ctx, queue_url: str, timeout_s: float = 90):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]
        time.sleep(1)
    raise AssertionError(f"no message received on {queue_url} within {timeout_s}s")


def _drain_and_bucket(ctx, queue_url: str, timeout_s: float, t0: float):
    """Drain every message currently deliverable within timeout_s, bucketed by its
    invalidationMarker detail field. Returns (buckets, first_seen_elapsed_s_by_marker)."""
    sqs = ctx.client("sqs")
    buckets: dict[str, list] = {}
    first_seen: dict[str, float] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            marker = json.loads(m["Body"])["detail"]["invalidationMarker"]
            buckets.setdefault(marker, []).append(m)
            first_seen.setdefault(marker, time.monotonic() - t0)
    return buckets, first_seen


def _wait_for_log_message(ctx, logs, function_name: str, needle: str, timeout_s: float = 60) -> None:
    """Poll CloudWatch Logs for `needle` in the function's log group -- the independent
    side-channel proving the handler actually ran (and raised), not just that it was named
    as a target."""
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{needle}"')
            if resp.get("events"):
                return
        except logs.exceptions.ResourceNotFoundException as exc:
            last_err = exc
        time.sleep(3)
    raise AssertionError(f"never observed {needle!r} in {log_group} within {timeout_s}s (last_err={last_err})")


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

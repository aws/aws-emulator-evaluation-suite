"""eventbridge-lambda-target-missing-permission-blocks-delivery."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-lambda-target-missing-permission-blocks-delivery"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda target without an events.amazonaws.com invoke grant is never invoked for a matching
    event (NO_PERMISSIONS, routed to the DLQ, no downstream effect), and granting the permission
    makes the identical wiring deliver; every PutEvents is asserted to have zero failed entries.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    ctx.client("lambda")

    obs_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-obs-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=obs_queue_url))
    obs_queue_arn = sqs.get_queue_attributes(
        QueueUrl=obs_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-dlq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    code = f"""
import json
import boto3
_sqs = boto3.client("sqs")
def handler(event, context):
    _sqs.send_message(QueueUrl={obs_queue_url!r}, MessageBody=json.dumps(event))
    return event
"""
    role_arn = _create_lambda_role(
        ctx,
        inline_statements=[
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": obs_queue_arn}
        ],
    )
    fn_name = ctx.unique_name("sim2real-fwd-")
    fn_arn = _create_lambda_function(ctx, fn_name, role_arn, code)
    _warm_up_role(ctx, fn_name, obs_queue_url)

    dist_id = "E" + uuid.uuid4().hex[:13].upper()
    event_source = ctx.unique_name("sim2real.cloudfront.dlqperm.")
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": [event_source],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {"requestParameters": {"distributionId": [dist_id]}},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    _grant_eventbridge_sqs(ctx, dlq_url, dlq_arn, rule_arn)

    # NOTE: deliberately NOT calling lam.add_permission() yet -- the target has no
    # resource-based policy allowing events.amazonaws.com to invoke it.
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "target-1",
                "Arn": fn_arn,
                "DeadLetterConfig": {"Arn": dlq_arn},
                "RetryPolicy": {
                    "MaximumRetryAttempts": 0,
                    "MaximumEventAgeInSeconds": 60,
                },
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target-1"]))

    marker_denied = "denied"
    # Re-published on a budget, for the same reason the positive control below is: the target
    # carries RetryPolicy.MaximumRetryAttempts=0, so ONE delivery attempt is all an event gets.
    # If the DLQ's own SQS policy (set moments earlier) has not propagated to EventBridge yet,
    # the failed delivery is dropped with nothing written anywhere, so a single publish can lose
    # the DLQ write.
    dlq_msg = _put_until_dlq(
        ctx, events, event_source, marker_denied, dist_id, dlq_url, timeout_s=180
    )

    # The function must never actually run.
    _assert_no_message(ctx, obs_queue_url, window_s=30)

    attrs = dlq_msg["MessageAttributes"]
    error_code = attrs["ERROR_CODE"]["StringValue"]
    assert error_code == "NO_PERMISSIONS", (
        f"expected DLQ ERROR_CODE=NO_PERMISSIONS, got {error_code!r}"
    )
    target_arn = attrs["TARGET_ARN"]["StringValue"]
    assert target_arn == fn_arn, (
        f"expected DLQ TARGET_ARN={fn_arn!r}, got {target_arn!r}"
    )
    body = json.loads(dlq_msg["Body"])
    assert body["detail"]["marker"] == marker_denied, (
        f"expected DLQ body detail.marker={marker_denied!r}, got {body['detail'].get('marker')!r}"
    )

    # Positive control: grant the permission, resend, and confirm delivery now works.
    #
    # Re-published on a budget rather than once. The target carries
    # RetryPolicy.MaximumRetryAttempts=0 (deliberately, so the negative leg above reaches the
    # DLQ on its FIRST attempt), which means a single event published while EventBridge is
    # still seeing the pre-AddPermission resource policy is denied and dropped with no retry,
    # i.e. a one-shot publish here is a coin flip
    # on lambda:AddPermission propagation, not a contract.
    _allow_eventbridge_invoke(ctx, fn_name, rule_arn)
    marker_allowed = "allowed"
    payload = _put_until_observed(
        ctx, events, event_source, marker_allowed, dist_id, obs_queue_url, timeout_s=180
    )
    assert payload["detail"]["marker"] == marker_allowed, (
        f"expected delivered message detail.marker={marker_allowed!r}, got {payload['detail'].get('marker')!r}"
    )


# ===== helpers =====
def _put_until_dlq(
    ctx, events, event_source: str, marker: str, dist_id: str, dlq_url: str, timeout_s: float
) -> dict:
    """Publish the marker event repeatedly until EventBridge's failed-delivery record for it
    shows up on the DLQ. Every publish is still asserted to be accepted by PutEvents, so this
    absorbs only DLQ-policy propagation, never a rejected entry."""
    deadline = time.monotonic() + timeout_s
    while True:
        _put_one_event(events, event_source, marker, dist_id)
        remaining = deadline - time.monotonic()
        msg = _poll_for_message_optional(
            ctx, dlq_url, timeout_s=min(30.0, max(5.0, remaining))
        )
        if msg is not None:
            body = json.loads(msg["Body"])
            if body.get("detail", {}).get("marker") == marker:
                return msg
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"EventBridge never wrote a failed-delivery record for the {marker!r} event to "
                f"{dlq_url} within {timeout_s}s"
            )


def _put_until_observed(
    ctx, events, event_source: str, marker: str, dist_id: str, obs_queue_url: str, timeout_s: float
) -> dict:
    """Publish the marker event repeatedly until the target Lambda forwards it to the
    observation queue, or the budget runs out. Every publish is still asserted to be accepted
    by PutEvents, so this absorbs only delivery-side propagation, never a rejected entry."""
    deadline = time.monotonic() + timeout_s
    while True:
        _put_one_event(events, event_source, marker, dist_id)
        remaining = deadline - time.monotonic()
        msg = _poll_for_message_optional(
            ctx, obs_queue_url, timeout_s=min(30.0, max(5.0, remaining))
        )
        if msg is not None:
            return json.loads(msg["Body"])
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the target Lambda never forwarded the {marker!r} event to {obs_queue_url} "
                f"within {timeout_s}s of being granted lambda:InvokeFunction"
            )


def _poll_for_message_optional(ctx, queue_url: str, timeout_s: float):
    """Receive one message, or None if none arrives inside the budget.

    MessageAttributeNames=["All"] is load-bearing: SQS omits MessageAttributes entirely unless
    they are requested, and EventBridge's failed-delivery metadata (ERROR_CODE, TARGET_ARN)
    travels there rather than in the body.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg
    return None


def _put_one_event(events, event_source: str, marker: str, dist_id: str) -> None:
    """Publish one CloudFront-shaped event and REFUSE to continue if PutEvents did not
    accept it. Without this, a per-entry rejection (e.g. the reserved "aws.*" source
    namespace) reads downstream as an absence of delivery, which is what this check is
    supposed to be measuring."""
    resp = events.put_events(
        Entries=[
            {
                "Source": event_source,
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(
                    {
                        "eventName": "CreateInvalidation",
                        "marker": marker,
                        "requestParameters": {"distributionId": dist_id},
                    }
                ),
            }
        ]
    )
    assert resp["FailedEntryCount"] == 0, (
        f"PutEvents refused the {marker!r} entry, so nothing was published and no delivery "
        f"conclusion can be drawn: {resp['Entries']}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    )
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-pol-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": inline_statements}
            ),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
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
                Tags={"sim2real": CHECK},
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


def _allow_eventbridge_invoke(
    ctx, function_name: str, rule_arn: str, statement_id: str = "AllowEventBridge"
) -> None:
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
        resp = lam.invoke(
            FunctionName=fn_name,
            Payload=b'{"warmup": true}',
            InvocationType="RequestResponse",
        )
        if resp.get("FunctionError"):
            last_err = resp["Payload"].read()
            time.sleep(3)
            continue
        break
    else:
        raise AssertionError(f"lambda role permissions never propagated: {last_err}")
    drain_deadline = time.monotonic() + 10
    while time.monotonic() < drain_deadline:
        r = sqs.receive_message(
            QueueUrl=obs_queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        )
        msgs = r.get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            sqs.delete_message(QueueUrl=obs_queue_url, ReceiptHandle=m["ReceiptHandle"])


def _grant_eventbridge_sqs(
    ctx, queue_url: str, queue_arn: str, rule_arn: str, sid: str = "AllowEventBridge"
) -> None:
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
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _assert_no_message(ctx, queue_url: str, window_s: float = 30) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        if msgs:
            raise AssertionError(
                f"function was invoked despite missing permission: {msgs[0]['Body']}"
            )
        time.sleep(1)


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

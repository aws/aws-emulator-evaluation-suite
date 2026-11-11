"""eventbridge-cloudfront-custom-event-denied-without-putevents-permission."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-cloudfront-custom-event-denied-without-putevents-permission"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]

_SOURCE = "sim2real.cloudfront.noperm"
_DETAIL_TYPE = "CloudFront Cache Purge Requested"
_SESSION_NAME = "sim2real-noperm-session"
_PROBE_SOURCE = "sim2real.cloudfront.noperm.probe"


@tags("axis:rejection", "cap:c7", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With an explicit Deny on events:PutEvents, a role's PutEvents fails with AccessDeniedException and its exact
    message and the rule's queue target receives nothing (depth 0); the same role without the Deny publishes the
    same event and it is delivered, both before the Deny is attached and after it is removed."""

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url, queue_arn = _create_queue(ctx)
    rule_name = ctx.unique_name("sim2real-cf-noperm-rule-")
    events = ctx.client("events")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]

    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t"]))

    iam = ctx.client("iam")
    role_name, role_arn = _create_allowed_role(ctx, iam, account_id)
    restricted_client = _assume_role_client(ctx, role_arn, "events")

    # --- Beat 1, positive control: the freshly assumed role, with only an Allow and no Deny yet,
    #     can publish and the event reaches the target. A bounded retry covers the allow policy's
    #     own propagation into the assumed session -- never a naked sleep.
    baseline_marker, _ = _poll_until_published(
        ctx,
        restricted_client,
        timeout_s=60,
        interval_s=3,
        description="the assumed role's allow policy propagates so PutEvents succeeds",
    )
    t_publish = time.monotonic()
    assert _message_arrives(ctx, queue_url, baseline_marker, timeout_s=60), (
        "baseline: the assumed role's PutEvents succeeded but its event never reached the target"
    )
    baseline_latency_s = time.monotonic() - t_publish

    # --- Break exactly one thing: an explicit Deny for events:PutEvents layered onto the SAME role.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "events:PutEvents", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="deny-putevents", PolicyDocument=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _drop_role_policy(iam, role_name, "deny-putevents"))

    denied_marker, denied_code, denied_message = _poll_until_denied(
        ctx,
        restricted_client,
        timeout_s=280,
        interval_s=3,
        description="the deny policy propagates so PutEvents is refused",
    )
    assert denied_code == "AccessDeniedException", (
        f"expected AccessDeniedException once the deny policy took effect, got {denied_code!r}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: events:PutEvents on resource: "
        f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default with an explicit deny in an "
        f"identity-based policy"
    )
    assert denied_message == expected_message, (
        f"expected message {expected_message!r}, got {denied_message!r}"
    )

    # The absence window is sized from this run's measured delivery latency, and the queue depth
    # backs the empty receive.
    absence_window_s = max(15.0, min(60.0, 3.0 * baseline_latency_s))
    assert not _message_arrives(ctx, queue_url, denied_marker, timeout_s=absence_window_s), (
        "the rule's target received an event even though PutEvents was denied"
    )
    approx = int(
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"])[
            "Attributes"
        ]["ApproximateNumberOfMessages"]
    )
    assert approx == 0, (
        f"expected zero messages on the queue after the denied window; ApproximateNumberOfMessages={approx}"
    )

    # --- Restore, same identity: removing the Deny lets the identical call succeed again.
    _drop_role_policy(iam, role_name, "deny-putevents")
    restored_marker, _ = _poll_until_published(
        ctx,
        restricted_client,
        timeout_s=120,
        interval_s=3,
        description="the deny's removal propagates so PutEvents succeeds again",
    )
    assert _message_arrives(ctx, queue_url, restored_marker, timeout_s=60), (
        "restore: PutEvents succeeded after the deny was removed, but the event never reached the target"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cf-noperm-q-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_allowed_role(ctx, iam, account_id: str) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-cf-noputevents-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=name, PolicyName="allow-putevents", PolicyDocument=json.dumps(allow_policy))
    ctx.on_cleanup(lambda: _drop_role_policy(iam, name, "allow-putevents"))
    return name, resp["Role"]["Arn"]


def _drop_role_policy(iam, role_name: str, policy_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _assume_role_client(ctx, role_arn: str, service: str) -> Any:
    sts = ctx.client("sts")
    last_err = None
    for _ in range(8):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            break
        except Exception as exc:  # noqa: BLE001 - trust propagation retry
            last_err = exc
            time.sleep(3)
    else:
        raise last_err

    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _publish(restricted_client, marker: str, source: str = _SOURCE) -> None:
    """Publish one marker event; a refusal raises its ClientError."""
    restricted_client.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )


def _publish_refused(restricted_client, marker: str) -> tuple[str, str | None]:
    """Publish one marker event and return the refusal's code and message; a success raises."""
    from botocore.exceptions import ClientError

    try:
        _publish(restricted_client, marker)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected PutEvents to be refused once the deny was in force, but it SUCCEEDED")


def _poll_until_published(ctx, restricted_client, *, timeout_s, interval_s, description):
    """Bounded retry (never a naked sleep): keep publishing fresh markers until one succeeds."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        marker = ctx.unique_name("marker-")
        try:
            _publish(restricted_client, marker)
            return marker, None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last code {code!r}")
        time.sleep(interval_s)


def _poll_until_denied(ctx, restricted_client, *, timeout_s, interval_s, description):
    """Bounded retry (never a naked sleep) until the Deny is in force, then publish the rule's event.

    The propagation probes use a source the rule does not match, so a probe published before the
    Deny takes effect never reaches the queue. Once three probes in a row are refused, one marker
    event the rule DOES match is published and its own outcome is returned.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    streak = 0
    code = None
    while streak < 3:
        try:
            _publish(restricted_client, ctx.unique_name("probe-"), source=_PROBE_SOURCE)
            code = None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
        streak = streak + 1 if code == "AccessDeniedException" else 0
        if streak >= 3:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last code {code!r}")
        time.sleep(interval_s)
    marker = ctx.unique_name("marker-")
    code, message = _publish_refused(restricted_client, marker)
    return marker, code, message


def _message_arrives(ctx, queue_url: str, marker: str, timeout_s: float) -> bool:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("detail", {}).get("marker") == marker:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

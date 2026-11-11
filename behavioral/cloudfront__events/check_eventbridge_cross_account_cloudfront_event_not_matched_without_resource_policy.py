"""eventbridge-cross-account-cloudfront-event-not-matched-without-resource-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-cross-account-cloudfront-event-not-matched-without-resource-policy"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]

_SESSION_NAME = "sim2real-outsider"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no permissions gets AccessDeniedException with the exact "no identity-based policy allows" message
    from PutEvents onto a custom bus, and the bus's rule delivers nothing; once the role is granted events:PutEvents
    on that bus, the same CloudFront-shaped event reaches the rule's queue."""
    events = ctx.client("events")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus_name)["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-obs-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    marker = ctx.unique_name("marker-")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": ["sim2real.cloudfront"], "detail": {"marker": [marker]}}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))

    _grant_eventbridge_sqs(ctx, queue_url, queue_arn, rule_arn)
    events.put_targets(
        Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "target-1", "Arn": queue_arn}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["target-1"]))

    # A principal with zero permissions of any kind: its only possible authorization
    # route is an identity-based grant added later (the positive-control step).
    role_name = ctx.unique_name("sim2real-behav-noperm-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    outsider = _assume_role_client(ctx, "events", role_arn)
    detail = json.dumps({"eventName": "CreateInvalidation", "marker": marker})
    entry = {
        "Source": "sim2real.cloudfront",
        "DetailType": "AWS API Call via CloudTrail",
        "EventBusName": bus_arn,
        "Detail": detail,
    }

    # 1) Without any grant, the unauthorized principal's PutEvents call itself is
    #    rejected -- nothing ever reaches the rule/target. (Retry past the brief
    #    window where a just-assumed role's credentials aren't yet recognized.)
    code, message = _first_call_denial(outsider, entry, timeout_s=30)
    assert code == "AccessDeniedException", (code, message)
    expected = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} is not authorized "
        f"to perform: events:PutEvents on resource: {bus_arn} because no identity-based policy "
        f"allows the events:PutEvents action"
    )
    assert message == expected, f"PutEvents denial message: expected {expected!r}, got {message!r}"
    _assert_no_message(ctx, queue_url, window_s=20)

    # 2) Granting that exact principal an identity-based events:PutEvents policy on
    #    this bus -- and nothing else -- authorizes the identical call (positive
    #    control): the same explicit-grant mechanism a foreign account would need.
    policy_name = ctx.unique_name("sim2real-behav-putevents-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    _wait_for_put_events_allowed(outsider, entry, timeout_s=60)

    msg = _poll_for_message(ctx, queue_url, timeout_s=60)
    body = json.loads(msg["Body"])
    delivered_marker = body["detail"]["marker"]
    assert delivered_marker == marker, f"expected marker {marker!r} at the consumer, got {delivered_marker!r}"


def _first_call_denial(client, entry: dict, timeout_s: float = 30) -> tuple[str, str]:
    """(code, message) of the PutEvents refusal once the fresh role's credentials are recognized.

    Retries only UnrecognizedClientException / InvalidClientTokenId (STS propagation). Raises when
    the call is accepted or the propagation window never closes.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = client.put_events(Entries=[entry])
        except ClientError as exc:
            err = exc.response["Error"]
            last = (err["Code"], err.get("Message", ""))
            if last[0] not in ("UnrecognizedClientException", "InvalidClientTokenId"):
                return last
            time.sleep(2)
            continue
        raise AssertionError(f"PutEvents by a principal with no grant was not refused: {resp!r}")
    raise AssertionError(f"the role's credentials were never recognized within {timeout_s}s: {last!r}")


def _assume_role_client(ctx, service: str, role_arn: str):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 30
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(2)
    if creds is None:
        raise AssertionError(f"could not assume role {role_arn}: {last_err}")
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _wait_for_put_events_allowed(client, entry: dict, timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = client.put_events(Entries=[entry])
            if resp.get("FailedEntryCount", 0) == 0:
                return
            last_code = resp["Entries"][0].get("ErrorCode")
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
        time.sleep(3)
    raise AssertionError(f"PutEvents never succeeded after granting the resource policy (last error: {last_code})")


def _grant_eventbridge_sqs(ctx, queue_url: str, queue_arn: str, rule_arn: str, sid: str = "AllowEventBridge") -> None:
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


def _assert_no_message(ctx, queue_url: str, window_s: float = 20) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            raise AssertionError(f"unexpected delivery from an unauthorized principal: {msgs[0]['Body']}")
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

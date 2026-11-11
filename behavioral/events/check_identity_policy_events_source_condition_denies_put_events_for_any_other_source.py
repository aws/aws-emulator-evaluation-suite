"""identity-policy-events-source-condition-denies-put-events-for-any-other-source."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-events-source-condition-denies-put-events-for-any-other-source"
GROUP = "enforcement"
SERVICES = ["events"]

_SESSION = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role allowed PutEvents only under events:source = S publishes S, but is refused for any
    other source, and a batch mixing S with another source is refused whole with neither entry
    delivered.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-evb-cond-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    allowed = ctx.unique_name("sim2real.allowed.")
    other = ctx.unique_name("sim2real.other.")
    rule = ctx.unique_name("sim2real-evb-condrule-")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": [allowed, other]})
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))
    queue_url, queue_arn = _queue_for_rule(ctx, sqs, rule_arn)
    events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["q"]))

    role_name, role_arn = _role(ctx, {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn,
            "Condition": {"StringEquals": {"events:source": allowed}},
        }],
    })
    scoped = ctx.client("events", creds=_assume(ctx, role_arn))

    ok_marker = ctx.unique_name("ok-")
    resp = _put_until_admitted(scoped, [_entry(bus, allowed, ok_marker)], timeout_s=90.0)
    assert resp["FailedEntryCount"] == 0, f"the allowed source was rejected per entry: {resp['Entries']!r}"
    got = _await_marker(sqs, queue_url, ok_marker, timeout_s=60.0)
    assert got["source"] == allowed, f"delivered event source was {got['source']!r}"

    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized "
        f"to perform: events:PutEvents on resource: {bus_arn} because no identity-based policy "
        f"allows the events:PutEvents action"
    )
    denied_marker = ctx.unique_name("denied-")
    code, message = _error(lambda: scoped.put_events(Entries=[_entry(bus, other, denied_marker)]))
    assert code == "AccessDeniedException", f"PutEvents for a source the condition excludes gave {code!r}"
    assert message == expected, f"refusal message was {message!r}"

    mixed_ok, mixed_other = ctx.unique_name("mixok-"), ctx.unique_name("mixother-")
    code, message = _error(lambda: scoped.put_events(
        Entries=[_entry(bus, allowed, mixed_ok), _entry(bus, other, mixed_other)]))
    assert code == "AccessDeniedException", f"a batch mixing the allowed and another source gave {code!r}"
    assert message == expected, f"mixed-batch refusal message was {message!r}"

    barrier = ctx.unique_name("barrier-")
    events.put_events(Entries=[_entry(bus, other, barrier)])
    seen = _drain_until(sqs, queue_url, barrier, timeout_s=60.0)
    leaked = sorted(m for m in (denied_marker, mixed_ok, mixed_other) if m in seen)
    assert leaked == [], f"entries of refused PutEvents calls were delivered: {leaked!r}"


def _entry(bus: str, source: str, marker: str) -> dict:
    return {"EventBusName": bus, "Source": source, "DetailType": "sim2real-condition",
            "Detail": json.dumps({"marker": marker})}


def _error(fn, timeout_s: float = 60.0):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails.

    A just-minted session token can be refused as unrecognized for a few seconds; that is
    retried, never returned.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "UnrecognizedClientException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _role(ctx, policy: dict) -> tuple[str, str]:
    """A role the account may assume, carrying exactly ``policy`` as its one inline policy."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-evb-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="scoped", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="scoped"))
    return name, arn


def _assume(ctx, role_arn: str, timeout_s: float = 60.0) -> dict:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            return {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(f"could not assume the check's role in {timeout_s}s: {last}")


def _put_until_admitted(client, entries: list, timeout_s: float) -> dict:
    """PutEvents until the new identity policy is in force (IAM propagation)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return client.put_events(Entries=entries)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"the role's identity policy never admitted the allowed source: {last}")


def _queue_for_rule(ctx, sqs, rule_arn: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evb-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    return url, arn


def _drain_until(sqs, url: str, marker: str, timeout_s: float) -> set:
    """Every marker received until ``marker`` arrives; fails if it never does."""
    seen: set = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            seen.add(json.loads(m["Body"]).get("detail", {}).get("marker"))
        if marker in seen:
            return seen
    raise AssertionError(f"marker {marker!r} never arrived; saw {sorted(map(str, seen))!r}")


def _await_marker(sqs, url: str, marker: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            body = json.loads(m["Body"])
            if body.get("detail", {}).get("marker") == marker:
                return body
    raise AssertionError(f"event {marker!r} was never delivered to the rule's queue in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

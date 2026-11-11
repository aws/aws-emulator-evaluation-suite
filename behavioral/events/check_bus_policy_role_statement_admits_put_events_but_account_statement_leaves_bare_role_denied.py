"""bus-policy-role-statement-admits-put-events-but-account-statement-leaves-bare-role-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bus-policy-role-statement-admits-put-events-but-account-statement-leaves-bare-role-denied"
GROUP = "enforcement"
SERVICES = ["events"]

_SESSION = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a bus whose policy allows one role by ARN and the account, a role with no identity policy
    named by ARN can PutEvents and its event is delivered, while the other stays AccessDenied: an
    account principal only delegates to the account's IAM policies."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-evb-pol-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    source = ctx.unique_name("sim2real.polrole.")
    rule = ctx.unique_name("sim2real-evb-polrule-")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": [source]})
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))
    queue_url, queue_arn = _queue_for_rule(ctx, sqs, rule_arn)
    events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["q"]))

    named_name, named_arn = _bare_role(ctx)
    other_name, other_arn = _bare_role(ctx)
    named_events = ctx.client("events", creds=_assume(ctx, named_arn))
    other_events = ctx.client("events", creds=_assume(ctx, other_arn))

    # Before any bus policy: an unpermissioned role is refused, naming the missing identity grant.
    code, message = _error(lambda: named_events.put_events(Entries=[_entry(bus, source, "pre")]))
    assert code == "AccessDeniedException", f"PutEvents by a role with no policy gave {code!r}"
    assert message == _no_identity_message(ctx, named_name, bus_arn), (
        f"PutEvents refusal message was {message!r}"
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowNamedRole",
                "Effect": "Allow",
                "Principal": {"AWS": named_arn},
                "Action": "events:PutEvents",
                "Resource": bus_arn,
            },
            {
                "Sid": "AllowOwnAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "events:PutEvents",
                "Resource": bus_arn,
            },
        ],
    }
    _put_bus_policy(events, bus, policy)
    ctx.on_cleanup(lambda: events.remove_permission(EventBusName=bus, RemoveAllPermissions=True))
    stored = json.loads(events.describe_event_bus(Name=bus)["Policy"])
    assert sorted(s["Sid"] for s in stored["Statement"]) == ["AllowNamedRole", "AllowOwnAccount"], (
        f"bus policy read back with statements {sorted(s.get('Sid') for s in stored['Statement'])!r}"
    )

    marker = ctx.unique_name("named-")
    resp = _put_until_admitted(named_events, _entry(bus, source, marker), timeout_s=90.0)
    assert resp["FailedEntryCount"] == 0, f"admitted PutEvents reported failed entries {resp['Entries']!r}"
    delivered = _await_marker(sqs, queue_url, marker, timeout_s=60.0)
    assert delivered["source"] == source, f"delivered event source was {delivered['source']!r}"

    # The policy document is live (its first statement just admitted a call), so its account
    # statement is live too: the unpermissioned role must still be refused, with the same reason.
    other_marker = ctx.unique_name("other-")
    code, message = _error(lambda: other_events.put_events(Entries=[_entry(bus, source, other_marker)]))
    assert code == "AccessDeniedException", (
        f"PutEvents by a role the bus policy grants only through its account statement gave {code!r}"
    )
    assert message == _no_identity_message(ctx, other_name, bus_arn), (
        f"refusal message under the account statement was {message!r}"
    )

    # Barrier: a second admitted event arrives after the refused one was attempted.
    marker2 = ctx.unique_name("named2-")
    named_events.put_events(Entries=[_entry(bus, source, marker2)])
    seen = _drain_until(sqs, queue_url, marker2, timeout_s=60.0)
    assert other_marker not in seen, "the refused role's event reached the rule's queue"


def _no_identity_message(ctx, role_name: str, bus_arn: str) -> str:
    return (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized "
        f"to perform: events:PutEvents on resource: {bus_arn} because no identity-based policy "
        f"allows the events:PutEvents action"
    )


def _entry(bus: str, source: str, marker: str) -> dict:
    return {"EventBusName": bus, "Source": source, "DetailType": "sim2real-policy",
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


def _put_bus_policy(events, bus: str, policy: dict, timeout_s: float = 60.0) -> None:
    """PutPermission, retried while a just-created role is not yet a resolvable principal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            events.put_permission(EventBusName=bus, Policy=json.dumps(policy))
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Message") != "Policy contains an invalid principal" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _bare_role(ctx) -> tuple[str, str]:
    """A role the account may assume, with no identity policy of any kind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-evb-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
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


def _put_until_admitted(client, entry: dict, timeout_s: float) -> dict:
    """PutEvents until the freshly attached bus policy admits the call (policy propagation)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return client.put_events(Entries=[entry])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"the bus policy statement naming the role never admitted it: {last}")


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

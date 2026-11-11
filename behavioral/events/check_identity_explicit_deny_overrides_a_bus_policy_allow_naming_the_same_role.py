"""identity-explicit-deny-overrides-a-bus-policy-allow-naming-the-same-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-explicit-deny-overrides-a-bus-policy-allow-naming-the-same-role"
GROUP = "enforcement"
SERVICES = ["events"]

_SESSION = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity-policy explicit Deny on PutEvents refuses a role (AccessDeniedException) even
    though the bus policy allows it by ARN; a role without the Deny is admitted, and removing the
    Deny admits it.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    bus = ctx.unique_name("sim2real-evb-deny-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    source = ctx.unique_name("sim2real.iddeny.")
    rule = ctx.unique_name("sim2real-evb-denyrule-")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": [source]})
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))
    queue_url, queue_arn = _queue_for_rule(ctx, sqs, rule_arn)
    events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["q"]))

    plain_name, plain_arn = _bare_role(ctx)
    denied_name, denied_arn = _bare_role(ctx)
    deny = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Action": "events:PutEvents", "Resource": bus_arn}]}
    iam.put_role_policy(RoleName=denied_name, PolicyName="deny", PolicyDocument=json.dumps(deny))
    ctx.on_cleanup(lambda: _delete_role_policy_if_present(iam, denied_name, "deny"))

    _put_bus_policy(events, bus, {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowBothRoles", "Effect": "Allow",
            "Principal": {"AWS": [plain_arn, denied_arn]},
            "Action": "events:PutEvents", "Resource": bus_arn,
        }],
    })
    ctx.on_cleanup(lambda: events.remove_permission(EventBusName=bus, RemoveAllPermissions=True))

    plain = ctx.client("events", creds=_assume(ctx, plain_arn))
    denied = ctx.client("events", creds=_assume(ctx, denied_arn))

    marker = ctx.unique_name("plain-")
    resp = _put_until_admitted(plain, _entry(bus, source, marker), timeout_s=90.0)
    assert resp["FailedEntryCount"] == 0, f"the plain role's PutEvents reported {resp['Entries']!r}"
    _await_marker(sqs, queue_url, marker, timeout_s=60.0)

    code, message, refused = _put_until_refused(
        denied, lambda m: _entry(bus, source, m), lambda: ctx.unique_name("refused-"), timeout_s=90.0)
    assert code == "AccessDeniedException", f"PutEvents by the role with an identity Deny gave {code!r}"
    assert message == _explicit_deny_message(ctx, denied_name, bus_arn), f"refusal message was {message!r}"

    iam.delete_role_policy(RoleName=denied_name, PolicyName="deny")
    restored = ctx.unique_name("restored-")
    resp = _put_until_admitted(denied, _entry(bus, source, restored), timeout_s=120.0)
    assert resp["FailedEntryCount"] == 0, f"PutEvents after removing the Deny reported {resp['Entries']!r}"
    seen = _drain_until(sqs, queue_url, restored, timeout_s=60.0)
    assert refused not in seen, "the event of the refused PutEvents reached the rule's queue"


def _delete_role_policy_if_present(iam, role: str, policy: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role, PolicyName=policy)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _explicit_deny_message(ctx, role_name: str, bus_arn: str) -> str:
    return (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized "
        f"to perform: events:PutEvents on resource: {bus_arn} with an explicit deny in an "
        f"identity-based policy"
    )


def _entry(bus: str, source: str, marker: str) -> dict:
    return {"EventBusName": bus, "Source": source, "DetailType": "sim2real-policy",
            "Detail": json.dumps({"marker": marker})}


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
    """PutEvents until a just-changed policy admits the call (policy propagation)."""
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
    raise AssertionError(f"PutEvents was never admitted: {last}")


def _put_until_refused(client, make_entry, new_marker, timeout_s: float) -> tuple:
    """PutEvents, each attempt with a fresh marker, until a just-attached Deny is in force.

    Returns the refusal's code and message and the marker of the refused attempt.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        marker = new_marker()
        try:
            client.put_events(Entries=[make_entry(marker)])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "UnrecognizedClientException":
                return err.get("Code"), err.get("Message"), marker
        time.sleep(3)
    raise AssertionError(f"the identity Deny never took effect within {timeout_s}s; PutEvents kept succeeding")


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

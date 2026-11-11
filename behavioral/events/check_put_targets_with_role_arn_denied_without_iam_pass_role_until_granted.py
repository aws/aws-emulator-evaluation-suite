"""put-targets-with-role-arn-denied-without-iam-pass-role-until-granted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-with-role-arn-denied-without-iam-pass-role-until-granted"
GROUP = "enforcement"
SERVICES = ["events"]

_SESSION = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Without iam:PassRole, PutTargets with a RoleArn is refused with AccessDenied naming PassRole
    on that role and stores nothing, while a role-less target attaches; once PassRole on exactly
    that role is granted, the role-bearing PutTargets succeeds and reads back with the role.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    bus = ctx.unique_name("sim2real-evb-src-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    dest = ctx.unique_name("sim2real-evb-dst-")
    dest_arn = events.create_event_bus(Name=dest, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=dest))

    rule = ctx.unique_name("sim2real-evb-passrule-")
    events.put_rule(Name=rule, EventBusName=bus,
                    EventPattern=json.dumps({"source": [ctx.unique_name("sim2real.pass.")]}))
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))
    ctx.on_cleanup(lambda: _remove_all_targets(events, rule, bus))

    target_role_name = ctx.unique_name("sim2real-evb-tgt-")
    target_role_arn = iam.create_role(
        RoleName=target_role_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=target_role_name))

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evb-q-"),
                                 tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url,
                                         AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    caller_name, caller_arn = _caller_role(ctx)
    base_policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": ["events:PutTargets", "events:RemoveTargets", "events:ListTargetsByRule"],
        "Resource": "*"}]}
    iam.put_role_policy(RoleName=caller_name, PolicyName="scoped", PolicyDocument=json.dumps(base_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=caller_name, PolicyName="scoped"))
    caller = ctx.client("events", creds=_assume(ctx, caller_arn))

    # Positive control: the caller CAN put targets (waits out IAM propagation of its policy).
    resp = _until_allowed(lambda: caller.put_targets(
        Rule=rule, EventBusName=bus, Targets=[{"Id": "queue", "Arn": queue_arn}]), timeout_s=90.0)
    assert resp["FailedEntryCount"] == 0, f"role-less PutTargets reported failures {resp['FailedEntries']!r}"

    bus_target = {"Id": "bus", "Arn": dest_arn, "RoleArn": target_role_arn}
    code, message = _error(lambda: caller.put_targets(Rule=rule, EventBusName=bus, Targets=[bus_target]))
    assert code == "AccessDeniedException", f"PutTargets with a RoleArn and no iam:PassRole gave {code!r}"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{caller_name}/{_SESSION} is not authorized "
        f"to perform: iam:PassRole on resource: {target_role_arn} because no identity-based policy "
        f"allows the iam:PassRole action"
    )
    assert message == expected, f"PassRole refusal message was {message!r}"

    ids = sorted(t["Id"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"])
    assert ids == ["queue"], f"after the refused PutTargets the rule's targets were {ids!r}"

    granted = json.loads(json.dumps(base_policy))
    granted["Statement"].append({"Effect": "Allow", "Action": "iam:PassRole", "Resource": target_role_arn})
    iam.put_role_policy(RoleName=caller_name, PolicyName="scoped", PolicyDocument=json.dumps(granted))

    resp = _until_allowed(lambda: caller.put_targets(Rule=rule, EventBusName=bus, Targets=[bus_target]),
                          timeout_s=90.0)
    assert resp["FailedEntryCount"] == 0, f"PutTargets after granting PassRole reported {resp['FailedEntries']!r}"
    stored = {t["Id"]: t for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]}
    assert sorted(stored) == ["bus", "queue"], f"targets after the grant were {sorted(stored)!r}"
    assert stored["bus"]["Arn"] == dest_arn and stored["bus"].get("RoleArn") == target_role_arn, (
        f"bus target read back as Arn={stored['bus']['Arn']!r} RoleArn={stored['bus'].get('RoleArn')!r}"
    )



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


def _until_allowed(fn, timeout_s: float):
    """Retry fn past AccessDeniedException while a just-written IAM policy propagates."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"the caller's policy never took effect: {last}")


def _caller_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-evb-caller-")
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


def _remove_all_targets(events, rule: str, bus: str) -> None:
    ids = [t["Id"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]]
    if ids:
        events.remove_targets(Rule=rule, EventBusName=bus, Ids=ids)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

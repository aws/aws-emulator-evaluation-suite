"""policy-scoped-to-one-bus-rules-denies-put-targets-on-the-same-rule-name-on-another-bus."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-scoped-to-one-bus-rules-denies-put-targets-on-the-same-rule-name-on-another-bus"
GROUP = "enforcement"
SERVICES = ["events"]

_SESSION = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Same-named rules on two buses are distinct IAM resources (rule/<bus>/<name>): a role allowed
    PutTargets only on busA's rules succeeds there and gets AccessDenied naming busB's rule ARN,
    leaving busB's rule with no target.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus_a = ctx.unique_name("sim2real-evb-a-")
    events.create_event_bus(Name=bus_a, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_a))
    bus_b = ctx.unique_name("sim2real-evb-b-")
    events.create_event_bus(Name=bus_b, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_b))

    rule = ctx.unique_name("sim2real-evb-same-")
    pattern = json.dumps({"source": [ctx.unique_name("sim2real.scope.")]})
    arn_a = events.put_rule(Name=rule, EventBusName=bus_a, EventPattern=pattern)["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus_a))
    arn_b = events.put_rule(Name=rule, EventBusName=bus_b, EventPattern=pattern)["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus_b))
    assert arn_a == f"arn:aws:events:{ctx.region}:{ctx.account}:rule/{bus_a}/{rule}", (
        f"busA's rule ARN has the shape {arn_a.replace(ctx.account, '<account>')!r}"
    )
    assert arn_b == f"arn:aws:events:{ctx.region}:{ctx.account}:rule/{bus_b}/{rule}", (
        f"busB's rule ARN has the shape {arn_b.replace(ctx.account, '<account>')!r}"
    )

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-evb-q-"),
                                 tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url,
                                         AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name, role_arn = _role(ctx, {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "events:PutTargets",
            "Resource": f"arn:aws:events:{ctx.region}:{ctx.account}:rule/{bus_a}/*",
        }],
    })
    scoped = ctx.client("events", creds=_assume(ctx, role_arn))
    target = [{"Id": "q", "Arn": queue_arn}]

    resp = _until_allowed(lambda: scoped.put_targets(Rule=rule, EventBusName=bus_a, Targets=target),
                          timeout_s=90.0)
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus_a, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, f"PutTargets on busA's rule reported {resp['FailedEntries']!r}"

    code, message = _error(lambda: scoped.put_targets(Rule=rule, EventBusName=bus_b, Targets=target))
    assert code == "AccessDeniedException", f"PutTargets on the same rule name on busB gave {code!r}"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized "
        f"to perform: events:PutTargets on resource: {arn_b} because no identity-based policy "
        f"allows the events:PutTargets action"
    )
    assert message == expected, f"PutTargets refusal message was {message!r}"

    on_a = [t["Arn"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus_a)["Targets"]]
    on_b = events.list_targets_by_rule(Rule=rule, EventBusName=bus_b)["Targets"]
    assert on_a == [queue_arn], f"busA's rule lists {len(on_a)} target(s), expected exactly the queue"
    assert on_b == [], f"busB's rule gained {len(on_b)} target(s) from a refused PutTargets"



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
    raise AssertionError(f"the role's policy never took effect: {last}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

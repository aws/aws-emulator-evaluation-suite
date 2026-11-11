"""put-targets-target-arn-condition-restricts-to-sqs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-target-arn-condition-restricts-to-sqs"
GROUP = "enforcement"
SERVICES = ["events", "iam", "sts", "sqs", "sns"]

_SESSION = "sim2real-behav"
# A session token AssumeRole just minted can be refused for a few seconds.
_TOKEN_NOT_YET_VALID = ("UnrecognizedClientException", "The security token included in the request is invalid.")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ForAnyValue:ArnLike events:TargetArn condition on PutTargets admits an SQS target and
    refuses an SNS one, which is not added to the rule.
    """
    events = ctx.client("events")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    rule = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": [ctx.unique_name("sim2real.")]}),
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"),
                                 tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    role_name, role_arn = _role(ctx, iam, {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "events:PutTargets", "Resource": rule_arn,
            "Condition": {"ForAnyValue:ArnLike": {"events:TargetArn": "arn:aws:sqs:*"}},
        }],
    })
    scoped = ctx.client("events", creds=_assume(ctx, role_arn))
    _denied = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized "
        f"to perform: events:PutTargets on resource: {rule_arn} because no identity-based policy "
        "allows the events:PutTargets action",
    )

    # --- the condition admits an SQS target, and it lands in ListTargetsByRule. ---
    _until_admitted(lambda: scoped.put_targets(
        Rule=rule, EventBusName=bus, Targets=[{"Id": "sqs", "Arn": queue_arn}],
    ), _denied)
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["sqs"]))
    targets = events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]
    assert {t["Id"]: t["Arn"] for t in targets} == {"sqs": queue_arn}, (
        f"targets after the admitted PutTargets were {targets!r}"
    )

    # --- the condition refuses an SNS target, which is not added. ---
    code, message = _error(lambda: scoped.put_targets(
        Rule=rule, EventBusName=bus, Targets=[{"Id": "sns", "Arn": topic_arn}],
    ))
    assert (code, message) == _denied, f"the SNS PutTargets gave {code!r} {message!r}"
    targets = events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]
    assert {t["Id"]: t["Arn"] for t in targets} == {"sqs": queue_arn}, (
        f"the refused PutTargets must add nothing; targets are now {targets!r}"
    )


def _role(ctx, iam, policy: dict) -> tuple[str, str]:
    """A role the account may assume, carrying exactly ``policy`` as its one inline policy."""
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "sts:AssumeRole",
    }]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="scoped", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="scoped"))
    return name, arn


def _assume(ctx, role_arn: str, timeout_s: float = 60.0) -> dict:
    """Credentials for ``role_arn``, retrying only the refusal a not-yet-propagated trust policy gives."""
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()["Arn"]
    unpropagated = (
        "AccessDenied",
        f"User: {caller} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
    )
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            return {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != unpropagated or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _error(fn, timeout_s: float = 60.0) -> tuple[str, str]:
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
            if (err.get("Code"), err.get("Message")) == _TOKEN_NOT_YET_VALID and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _until_admitted(fn, denied: tuple[str, str], timeout_s: float = 90.0):
    """Retry fn() while a just-attached identity policy propagates: only ``denied`` or a
    not-yet-valid session token is retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) not in (denied, _TOKEN_NOT_YET_VALID):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the role's identity policy never admitted the call in {timeout_s}s: {exc}"
                ) from exc
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

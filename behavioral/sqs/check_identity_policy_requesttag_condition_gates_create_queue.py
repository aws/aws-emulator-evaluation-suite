"""identity-policy-requesttag-condition-gates-create-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-requesttag-condition-gates-create-queue"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-reqtag"
TAG_KEY = "team"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A role whose identity policy allows sqs:CreateQueue only when aws:RequestTag/team
    equals "a" creates a queue carrying team=a, then is refused CreateQueue without that
    tag and again with the tag set to "b", and neither refused call creates a queue.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    role_name, role_arn = _create_role(ctx, account)
    _put_role_policy(
        ctx,
        role_name,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sqs:CreateQueue",
                    "Resource": "*",
                    "Condition": {"StringEquals": {f"aws:RequestTag/{TAG_KEY}": "a"}},
                },
                {
                    "Effect": "Allow",
                    "Action": ["sqs:DeleteQueue", "sqs:GetQueueAttributes", "sqs:ListQueueTags", "sqs:TagQueue"],
                    "Resource": "*",
                },
            ],
        },
    )
    restricted_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))
    caller_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"

    # Propagation first: the call carrying the tag value the condition requires succeeds, so
    # the denials below come from the condition, not from a policy not yet in effect.
    name_tag_a = ctx.unique_name("sim2real-behav-reqtag-taga-")
    url_a = _until_allowed(
        lambda: restricted_sqs.create_queue(QueueName=name_tag_a, tags={TAG_KEY: "a", "sim2real": CHECK}),
        timeout_s=_budget_s(ctx, 120.0),
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: restricted_sqs.delete_queue(QueueUrl=url_a), "AWS.SimpleQueueService.NonExistentQueue"))

    live_tags = restricted_sqs.list_queue_tags(QueueUrl=url_a).get("Tags", {})
    assert live_tags.get(TAG_KEY) == "a", f"the created queue must carry {TAG_KEY}=a, got {live_tags!r}"

    name_no_tag = ctx.unique_name("sim2real-behav-reqtag-notag-")
    ctx.on_cleanup(_delete_if_exists(ctx, name_no_tag))
    err_no_tag = _error(lambda: restricted_sqs.create_queue(QueueName=name_no_tag))
    assert err_no_tag.get("Code") == "AccessDenied", f"expected AccessDenied with no tag, got {err_no_tag!r}"
    assert err_no_tag.get("Message") == _denied_message(caller_arn, region, account, name_no_tag), f"got {err_no_tag!r}"

    name_tag_b = ctx.unique_name("sim2real-behav-reqtag-tagb-")
    ctx.on_cleanup(_delete_if_exists(ctx, name_tag_b))
    err_tag_b = _error(lambda: restricted_sqs.create_queue(QueueName=name_tag_b, tags={TAG_KEY: "b"}))
    assert err_tag_b.get("Code") == "AccessDenied", f"expected AccessDenied with team=b, got {err_tag_b!r}"
    assert err_tag_b.get("Message") == _denied_message(caller_arn, region, account, name_tag_b), f"got {err_tag_b!r}"

    # Effect absent: neither refused CreateQueue call created a queue.
    assert not _queue_exists(ctx, name_no_tag), f"CreateQueue without the tag must not have created {name_no_tag!r}"
    assert not _queue_exists(ctx, name_tag_b), f"CreateQueue with team=b must not have created {name_tag_b!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _denied_message(caller_arn: str, region: str, account: str, queue_name: str) -> str:
    """The exact AccessDenied message real SQS returns when CreateQueue's own request
    tags do not satisfy the identity policy's aws:RequestTag condition."""
    queue_arn = f"arn:aws:sqs:{region}:{account}:{queue_name}"
    return (
        f"User: {caller_arn} is not authorized to perform: sqs:createqueue on resource: {queue_arn} "
        f"because no identity-based policy allows the sqs:createqueue action"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _until_allowed(fn, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc.response["Error"]["Code"]
        if time.monotonic() > deadline:
            raise TimeoutError(f"call never became allowed within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _delete_if_exists(ctx, name):
    """A teardown deleting the named queue if a refused CreateQueue created it anyway."""
    sqs = ctx.client("sqs")

    def run_undo() -> None:
        try:
            url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
                return
            raise

    return run_undo


def _queue_exists(ctx, name) -> bool:
    sqs = ctx.client("sqs")
    try:
        sqs.get_queue_url(QueueName=name)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            return False
        raise


def _create_role(ctx, account):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-reqtag-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return name, role["Arn"]


def _put_role_policy(ctx, role_name, doc):
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-behav-reqtag-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity")
    )
    return policy_name


def _assume(ctx, role_arn, *, interval_s=3.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION)["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            if time.monotonic() > deadline:
                raise TimeoutError(f"role {role_arn} was never assumable") from exc
            time.sleep(interval_s)
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

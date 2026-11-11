"""attach-same-managed-policy-twice-is-idempotent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-same-managed-policy-twice-is-idempotent"
GROUP = "attach_detach"
SERVICES = ["iam"]

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _converge(read, expected, *, budget_s: float = 30.0, poll_s: float = 2.0):
    """``read()`` once it equals ``expected``, else its last value when the budget runs out.

    IAM reads are eventually consistent, so convergence is asserted, never an immediate read.
    """
    deadline = time.monotonic() + budget_s
    while True:
        value = read()
        if value == expected or time.monotonic() >= deadline:
            return value
        time.sleep(poll_s)


def _attached(pages, policy_arn: str) -> int:
    return sum(1 for p in pages for a in p["AttachedPolicies"] if a["PolicyArn"] == policy_arn)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Attaching one managed policy twice to a role, a user and a group lists it once per entity
    with AttachmentCount 3; each single detach drops the count to 2, 1 and 0, and a second detach
    fails with NoSuchEntity and the exact "was not found" message."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-att2-")
    path = f"/{name}/"

    policy_arn = iam.create_policy(PolicyName=name, Path=path, PolicyDocument=_POLICY)["Policy"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_policy(PolicyArn=policy_arn), "NoSuchEntity"))

    iam.create_role(RoleName=name, Path=path, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.create_user(UserName=name, Path=path)
    ctx.on_cleanup(_teardown(lambda: iam.delete_user(UserName=name), "NoSuchEntity"))
    iam.create_group(GroupName=name, Path=path)
    ctx.on_cleanup(_teardown(lambda: iam.delete_group(GroupName=name), "NoSuchEntity"))

    entities = [
        ("role", lambda: iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn),
         lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn),
         lambda: _attached(iam.get_paginator("list_attached_role_policies").paginate(RoleName=name), policy_arn)),
        ("user", lambda: iam.attach_user_policy(UserName=name, PolicyArn=policy_arn),
         lambda: iam.detach_user_policy(UserName=name, PolicyArn=policy_arn),
         lambda: _attached(iam.get_paginator("list_attached_user_policies").paginate(UserName=name), policy_arn)),
        ("group", lambda: iam.attach_group_policy(GroupName=name, PolicyArn=policy_arn),
         lambda: iam.detach_group_policy(GroupName=name, PolicyArn=policy_arn),
         lambda: _attached(iam.get_paginator("list_attached_group_policies").paginate(GroupName=name), policy_arn)),
    ]

    for kind, attach, detach, count in entities:
        first = attach()["ResponseMetadata"]["HTTPStatusCode"]
        ctx.on_cleanup(_teardown(detach, "NoSuchEntity"))
        second = attach()["ResponseMetadata"]["HTTPStatusCode"]
        assert (first, second) == (200, 200), f"attaching to the {kind} twice answered {first} then {second}"
        listed = _converge(count, 1)
        assert listed == 1, f"the {kind} lists the policy {listed} times after two attaches, expected once"

    attachment_count = _converge(lambda: iam.get_policy(PolicyArn=policy_arn)["Policy"]["AttachmentCount"], 3)
    assert attachment_count == 3, (
        f"AttachmentCount is {attachment_count} after attaching twice to each of 3 entities, expected 3"
    )

    entities_for_policy = {"roles": 0, "users": 0, "groups": 0}
    for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=policy_arn):
        entities_for_policy["roles"] += sum(1 for r in page["PolicyRoles"] if r["RoleName"] == name)
        entities_for_policy["users"] += sum(1 for u in page["PolicyUsers"] if u["UserName"] == name)
        entities_for_policy["groups"] += sum(1 for g in page["PolicyGroups"] if g["GroupName"] == name)
    assert entities_for_policy == {"roles": 1, "users": 1, "groups": 1}, (
        f"ListEntitiesForPolicy counts {entities_for_policy!r}, expected each entity exactly once"
    )

    expected_count = 3
    for kind, _attach, detach, count in entities:
        detach()
        expected_count -= 1
        listed = _converge(count, 0)
        assert listed == 0, f"the {kind} still lists the policy {listed} time(s) after one detach"
        now = _converge(
            lambda: iam.get_policy(PolicyArn=policy_arn)["Policy"]["AttachmentCount"], expected_count
        )
        assert now == expected_count, (
            f"AttachmentCount is {now} after detaching the {kind} once, expected {expected_count}"
        )
        code, msg = _error(detach)
        assert code == "NoSuchEntity", f"a second detach from the {kind} gave {code!r}, expected NoSuchEntity"
        assert msg == f"Policy {policy_arn} was not found.", f"second detach from the {kind}: message {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

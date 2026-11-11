"""tag-resource-too-many-tags-limit."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-too-many-tags-limit"
GROUP = 'tagging'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    }
)


def _create_sfn_role(ctx):
    """Create an execution role Step Functions can assume; it is deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for fn in (
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)
    return arn


def _await_role(fn, *, timeout_s=90.0):
    """Call fn(), retrying AccessDeniedException while a new role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    arn = _await_role(lambda: sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type=sm_type,
    ))["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource enforces the 50-tag quota atomically: a call pushing past 50 fails TooManyTags
    and applies none of its tags, and the identical call succeeds once room is freed."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}
    arn = _create_state_machine(ctx, definition)

    base_count = len(sfn.list_tags_for_resource(resourceArn=arn)["tags"])
    room = 50 - base_count
    assert room > 0, f"base tags already at/over the 50 quota: {base_count}"

    filler_tags = [{"key": f"sim2real-behav-fill-{i}", "value": str(i)} for i in range(room)]
    sfn.tag_resource(resourceArn=arn, tags=filler_tags)

    at_limit = sfn.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(at_limit) == 50, f"expected exactly 50 tags at the quota boundary, got {len(at_limit)}"

    overflow_tags = [{"key": f"sim2real-behav-overflow-{i}", "value": str(i)} for i in range(3)]
    code, message = _error(lambda: sfn.tag_resource(resourceArn=arn, tags=overflow_tags))
    assert code == "TooManyTags", f"expected TooManyTags pushing past the 50-tag quota, got {code}"
    assert message == "Too many tags provided.", f"unexpected TooManyTags message: {message!r}"

    after = sfn.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(after) == 50, (
        f"a rejected TagResource call must apply NONE of its tags (atomic), got {len(after)} tags"
    )
    overflow_keys = {t["key"] for t in overflow_tags}
    assert not any(t["key"] in overflow_keys for t in after), "no overflow tag key must have been applied"

    freed_keys = [t["key"] for t in filler_tags[: len(overflow_tags)]]
    sfn.untag_resource(resourceArn=arn, tagKeys=freed_keys)
    freed = sfn.list_tags_for_resource(resourceArn=arn)["tags"]
    assert len(freed) == 50 - len(overflow_tags), (
        f"expected {50 - len(overflow_tags)} tags after freeing room for the retry, got {len(freed)}"
    )

    sfn.tag_resource(resourceArn=arn, tags=overflow_tags)
    restored = sfn.list_tags_for_resource(resourceArn=arn)["tags"]
    restored_keys = {t["key"] for t in restored}
    assert overflow_keys <= restored_keys, (
        f"the identical TagResource call must succeed once room exists, missing {overflow_keys - restored_keys}"
    )
    assert len(restored) == 50, f"expected exactly 50 tags after the restored call, got {len(restored)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""tag-untagged-resource-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untagged-resource-not-found"
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
    """Call fn(); return the (code, message) of its ClientError. A success raises, because a
    target accepting what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource on a fully deleted state machine fails with ResourceNotFound and the exact message,
    while ListTagsForResource on it returns an empty tag set; on the live state machine TagResource and
    UntagResource add and remove the tag."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}
    arn = _create_state_machine(ctx, definition)

    # Positive control: UntagResource must genuinely work against a LIVE state
    # machine, so the ResourceNotFound asserted below is attributable to the
    # resource being gone -- not to UntagResource rejecting every call regardless
    # of target.
    sfn.tag_resource(resourceArn=arn, tags=[{"key": "sim2real-behav-live", "value": "x"}])
    live_tags = {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=arn).get("tags", [])}
    assert live_tags.get("sim2real-behav-live") == "x", f"expected tag on a live state machine, got {live_tags}"
    sfn.untag_resource(resourceArn=arn, tagKeys=["sim2real-behav-live"])
    live_tags = {t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=arn).get("tags", [])}
    assert "sim2real-behav-live" not in live_tags, (
        f"expected UntagResource to remove the key from a live state machine, got {live_tags}"
    )

    sfn.delete_state_machine(stateMachineArn=arn)

    deadline = time.monotonic() + 270
    gone = False
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "StateMachineDoesNotExist":
                gone = True
                break
        time.sleep(5)
    assert gone, "state machine was not fully removed before exercising tag APIs on it"

    code, message = _error(lambda: sfn.untag_resource(resourceArn=arn, tagKeys=["sim2real-behav-nope"]))
    assert code == "ResourceNotFound", f"expected ResourceNotFound from UntagResource, got {code}"
    assert message == f"Resource not found: '{arn}'", f"unexpected ResourceNotFound message: {message!r}"

    listed = sfn.list_tags_for_resource(resourceArn=arn)
    assert listed.get("tags", []) == [], f"expected no tags for a fully deleted resource, got {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

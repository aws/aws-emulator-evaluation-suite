"""list-tags-contrasts-untagged-and-create-time-tagged-then-refuses-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-contrasts-untagged-and-create-time-tagged-then-refuses-after-delete"
GROUP = "tagging"
SERVICES = ["iam", "stepfunctions"]

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


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx, iam) -> str:
    """Create an execution role Step Functions can assume; deleted at teardown."""
    role_name = ctx.unique_name("sim2real-behav-sfntag-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return arn


def _await_role(fn, *, timeout_s: float = 90.0):
    """Call ``fn``, retrying while a just-created role's trust policy is not yet effective."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _list_tags_map(sfn, resource_arn: str) -> dict:
    resp = sfn.list_tags_for_resource(resourceArn=resource_arn)
    return {t["key"]: t["value"] for t in resp.get("tags", [])}


def _error(fn):
    """(code, message) of the refused call; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource is empty on an untagged state machine, holds exactly a create-time tag
    on another, and both tags after TagResource adds a second one. After DeleteStateMachine it is
    empty again and TagResource fails with ResourceNotFound naming the ARN.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})

    role_arn = _create_sfn_role(ctx, iam)

    plain_name = ctx.unique_name("sim2real-behav-sfntag-plain-")
    plain_arn = _await_role(
        lambda: sfn.create_state_machine(
            name=plain_name, definition=definition, roleArn=role_arn, type="STANDARD",
        )
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=plain_arn)))
    plain_tags = _list_tags_map(sfn, plain_arn)
    assert plain_tags == {}, f"expected no tags on an untagged state machine, got {plain_tags!r}"

    tagged_name = ctx.unique_name("sim2real-behav-sfntag-tagged-")
    tagged_arn = sfn.create_state_machine(
        name=tagged_name,
        definition=definition,
        roleArn=role_arn,
        type="STANDARD",
        tags=[{"key": "a", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=tagged_arn)))
    created_tags = _list_tags_map(sfn, tagged_arn)
    assert created_tags == {"a": "1"}, f"expected exactly the create-time tag, got {created_tags!r}"

    sfn.tag_resource(resourceArn=tagged_arn, tags=[{"key": "b", "value": "2"}])
    merged_tags = _list_tags_map(sfn, tagged_arn)
    assert merged_tags == {"a": "1", "b": "2"}, (
        f"expected both the create-time and the TagResource-added tag, got {merged_tags!r}"
    )

    sfn.delete_state_machine(stateMachineArn=tagged_arn)
    deadline = time.monotonic() + 270
    gone = False
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=tagged_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "StateMachineDoesNotExist":
                gone = True
                break
        time.sleep(5)
    assert gone, "state machine was not fully removed before exercising tag APIs on it"

    deleted_tags = _list_tags_map(sfn, tagged_arn)
    assert deleted_tags == {}, f"expected no tags for a fully deleted resource, got {deleted_tags!r}"

    code, message = _error(
        lambda: sfn.tag_resource(resourceArn=tagged_arn, tags=[{"key": "c", "value": "3"}])
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound from TagResource, got {code!r}"
    assert message == f"Resource not found: '{tagged_arn}'", f"unexpected ResourceNotFound message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

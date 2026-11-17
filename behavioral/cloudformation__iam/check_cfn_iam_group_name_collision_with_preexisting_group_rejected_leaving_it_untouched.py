"""cfn-iam-group-name-collision-with-preexisting-group-rejected-leaving-it-untouched."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-group-name-collision-with-preexisting-group-rejected-leaving-it-untouched"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_STACK_CAP_S = 300.0


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose AWS::IAM::Group names a GroupName IAM already holds attempts the create,
    has its resource handler refuse with AlreadyExists, rolls the stack back to nothing, and
    leaves the pre-existing group untouched.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-group.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-cfnreal-grpcol-")
    stack_name = ctx.unique_name("sim2real-cfnreal-grpcol-stack-")
    free_name = ctx.unique_name("sim2real-cfnreal-grpcol-b-")

    # The contested group exists outside any stack, created the way a customer's console or CLI
    # would, so CloudFormation's own handler is the only thing it must contend with.
    ctx.on_cleanup(lambda: _retire_group(iam, group_name))
    original = iam.create_group(GroupName=group_name)["Group"]

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_body(group_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _retire_stack(cfn, stack_id))

    status = _settle(ctx, cfn, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    events = _events(cfn, stack_id)
    failed = [e for e in events
              if e["LogicalResourceId"] == "Group" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, f"expected exactly one Group CREATE_FAILED event, got {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    before, _, after = reason.partition(" (RequestToken: ")
    want_before = (
        "Resource handler returned message: "
        f'"Resource of type \'AWS::IAM::Group\' with identifier \'{group_name}\' already exists."'
    )
    assert before == want_before, f"CREATE_FAILED reason prefix {before!r} != {want_before!r}"
    assert after.endswith(", HandlerErrorCode: AlreadyExists)"), (
        f"CREATE_FAILED reason suffix {after!r} does not end in the expected HandlerErrorCode"
    )

    resources = _paginate(cfn, "list_stack_resources", "StackResourceSummaries", StackName=stack_id)
    group_resources = [r for r in resources if r["LogicalResourceId"] == "Group"]
    assert len(group_resources) == 1 and group_resources[0]["ResourceStatus"] == "DELETE_COMPLETE", (
        f"the rolled-back Group resource must end DELETE_COMPLETE, got {group_resources!r}"
    )

    # The direct call the validation is standing in for raises IAM's own exact refusal.
    want = ("EntityAlreadyExists", f"Group with name {group_name} already exists.")
    got = _error(lambda: iam.create_group(GroupName=group_name))
    assert got == want, f"expected {want!r}, got {got!r}"

    # Positive control: the identical template with a name nothing holds creates cleanly.
    free_stack = ctx.unique_name("sim2real-cfnreal-grpcol-okstack-")
    free_stack_id = cfn.create_stack(
        StackName=free_stack,
        TemplateBody=_body(free_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _retire_stack(cfn, free_stack_id))
    free_status = _settle(ctx, cfn, free_stack_id)
    assert free_status == "CREATE_COMPLETE", f"the control stack ended {free_status!r}"
    assert iam.get_group(GroupName=free_name)["Group"]["GroupName"] == free_name

    # The pre-existing group under the contested name is exactly as it was.
    survivor = iam.get_group(GroupName=group_name)["Group"]
    assert (survivor["GroupId"], survivor["Arn"]) == (original["GroupId"], original["Arn"]), (
        f"the pre-existing group changed: {survivor!r} vs original {original!r}"
    )


def _body(group_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {"Type": "AWS::IAM::Group", "Properties": {"GroupName": group_name}},
        },
    })


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _budget_s(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _settle(ctx, cfn, stack_id: str) -> str:
    deadline = time.monotonic() + _budget_s(ctx, _STACK_CAP_S)
    while True:
        status = _stack(cfn, stack_id)["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id!r} not terminal; last status {status!r}")
        time.sleep(2.0)


def _paginate(client, op: str, key: str, **kw) -> list:
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _events(cfn, stack_id: str) -> list[dict]:
    return _paginate(cfn, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _retire_group(iam, name: str) -> None:
    try:
        iam.delete_group(GroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retire_stack(cfn, stack_id: str) -> None:
    status = _stack(cfn, stack_id)["StackStatus"]
    while status.endswith("_IN_PROGRESS"):
        time.sleep(2.0)
        status = _stack(cfn, stack_id)["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    while True:
        status = _stack(cfn, stack_id)["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        time.sleep(2.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"teardown stack {stack_id} ended {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

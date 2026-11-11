"""compute-environment-tag-change-forces-replacement."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "compute-environment-tag-change-forces-replacement"
GROUP = "deploy"
SERVICES = ["batch", "cloudformation", "iam"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(tag_value: str) -> str:
    return json.dumps({
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "batch.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"],
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "CE": {
                "Type": "AWS::Batch::ComputeEnvironment",
                "Properties": {
                    "Type": "UNMANAGED",
                    "ServiceRole": {"Fn::GetAtt": ["Role", "Arn"]},
                    "Tags": {"sim2real-env": tag_value},
                },
            },
        },
        "Outputs": {"CEArn": {"Value": {"Ref": "CE"}}},
    })


def _wait_terminal(cf, stack_id: str, *, timeout_s: float = 300.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} terminal not met within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id, timeout_s=timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended in {status!r}, expected DELETE_COMPLETE")


def _ordered_decisive_events(cf, stack_id: str) -> list:
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    events = [e for page in pages for e in page["StackEvents"]]
    events.reverse()
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if e["ResourceStatus"] in _TERMINAL
    ]


def _is_subsequence(want: list, seq: list) -> bool:
    it = iter(seq)
    return all(any(row == w for row in it) for w in want)


def _ce_arns(batch, arns: list[str]) -> list[str]:
    found = batch.describe_compute_environments(computeEnvironments=arns)["computeEnvironments"]
    return sorted(ce["computeEnvironmentArn"] for ce in found)


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """AWS::Batch::ComputeEnvironment's schema marks Tags createOnly (tagUpdatable=false): an
    UpdateStack that changes only Tags replaces the compute environment with a new ARN, deletes
    the old one in the cleanup phase, and Batch's own DescribeComputeEnvironments drops it.
    """
    cf = ctx.client("cloudformation")
    batch = ctx.client("batch")
    iam = ctx.client("iam")

    stack_name = ctx.unique_name("sim2real-behav-cetag-")
    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template("v1"), Capabilities=["CAPABILITY_IAM"]
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, stack_id))
    status = _wait_terminal(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"setup stack {stack_name!r} ended in {status!r}"

    role_name = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Role")[
        "StackResourceDetail"]["PhysicalResourceId"]
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    before_arn = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"][0]["OutputValue"]
    before = batch.describe_compute_environments(computeEnvironments=[before_arn])[
        "computeEnvironments"][0]
    assert before["tags"] == {"sim2real-env": "v1"}, before["tags"]
    assert (before["type"], before.get("serviceRole")) == ("UNMANAGED", role_arn), (
        f"compute environment reads back type {before['type']!r}; serviceRole is the stack role: "
        f"{before.get('serviceRole') == role_arn!r}"
    )

    cf.update_stack(
        StackName=stack_id, TemplateBody=_template("v2"), Capabilities=["CAPABILITY_IAM"]
    )
    status = _wait_terminal(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack_name!r} update ended in {status!r}"

    decisive = _ordered_decisive_events(cf, stack_id)
    want = [
        ("CE", "CREATE_COMPLETE"), (stack_name, "CREATE_COMPLETE"),
        ("CE", "UPDATE_COMPLETE"), ("CE", "DELETE_COMPLETE"), (stack_name, "UPDATE_COMPLETE"),
    ]
    assert _is_subsequence(want, decisive), (
        f"a replacement deletes the old CE in the cleanup phase: expected the ordered subsequence "
        f"{want!r} in {decisive!r}"
    )

    after_arn = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"][0]["OutputValue"]
    assert after_arn != before_arn, (
        f"the compute environment ARN stayed {after_arn!r} across a Tags-only update; the "
        f"createOnly Tags property should have forced a replacement"
    )

    # Batch may list a just-deleted compute environment briefly; poll to convergence.
    deadline = time.monotonic() + 60
    found_arns = _ce_arns(batch, [before_arn, after_arn])
    while found_arns != [after_arn] and time.monotonic() < deadline:
        time.sleep(3)
        found_arns = _ce_arns(batch, [before_arn, after_arn])
    assert found_arns == [after_arn], (
        f"DescribeComputeEnvironments for [before, after] returned {found_arns!r}; the "
        f"replaced compute environment {before_arn!r} must be gone and only {after_arn!r} remain"
    )
    after = batch.describe_compute_environments(computeEnvironments=[after_arn])[
        "computeEnvironments"][0]
    assert after["tags"] == {"sim2real-env": "v2"}, after["tags"]
    assert (after["type"], after.get("serviceRole")) == ("UNMANAGED", role_arn), (
        f"replacement reads back type {after['type']!r}; serviceRole is the stack role: "
        f"{after.get('serviceRole') == role_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

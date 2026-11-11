"""nested-stack-parentage-and-cascade-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-stack-parentage-and-cascade-delete"
GROUP = 'nested_stacks'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _describe_error(cf, name):
    """(Code, Message) from DescribeStacks; an unexpected success raises."""
    try:
        result = cf.describe_stacks(StackName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected DescribeStacks({name}) to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _wait_terminal(cf, name, *, timeout_s=900, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _make_bucket(ctx, s3):
    """Create a region-correct bucket and register object+bucket teardown."""
    bucket = ctx.unique_name("sim2real-behav-nested-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _param_exists(ssm, name):
    """True iff the SSM parameter exists (ParameterNotFound => False)."""
    try:
        ssm.get_parameter(Name=name)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ParameterNotFound":
            return False
        raise


def _child_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Seed": {"Type": "String"},
            "ParamName": {"Type": "String"},
        },
        "Resources": {
            "ChildParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": {"Ref": "ParamName"},
                    "Type": "String",
                    "Value": {"Fn::Sub": "${Seed}-child"},
                },
            },
        },
        "Outputs": {
            "ChildValue": {"Value": {"Fn::GetAtt": ["ChildParam", "Value"]}},
            "ChildParamName": {"Value": {"Ref": "ChildParam"}},
        },
    })


def _parent_template(template_url, seed, param_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Child": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {
                    "TemplateURL": template_url,
                    "Parameters": {"Seed": seed, "ParamName": param_name},
                },
            },
        },
        "Outputs": {
            # The canonical nested-stack cross-reference form.
            "FromChild": {"Value": {"Fn::GetAtt": ["Child", "Outputs.ChildValue"]}},
            "ChildRef": {"Value": {"Ref": "Child"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::CloudFormation::Stack creates a child stack whose ParentId/RootId name the parent,
    its outputs resolve via Fn::GetAtt Child.Outputs.X, and deleting the parent cascades to the
    child and its resources; the deleted parent is then unknown by name but describable by StackId.
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")

    bucket = _make_bucket(ctx, s3)
    key = "child.template.json"
    s3.put_object(Bucket=bucket, Key=key, Body=_child_template().encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    template_url = ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}", bucket, key)

    seed = "sim2real"
    child_param = "/" + ctx.unique_name("sim2real-behav-nested-p-")
    parent = ctx.unique_name("sim2real-behav-nested-parent-")

    cf.create_stack(
        StackName=parent,
        TemplateBody=_parent_template(template_url, seed, child_param),
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=parent))
    parent_obj = _wait_terminal(cf, parent)
    assert parent_obj["StackStatus"] == "CREATE_COMPLETE", (
        f"the parent stack must reach CREATE_COMPLETE, got {parent_obj['StackStatus']!r}: "
        f"{parent_obj.get('StackStatusReason')!r}"
    )
    parent_id = parent_obj["StackId"]

    # The nested resource must be backed by a real, separate stack.
    resources = {
        r["LogicalResourceId"]: r
        for r in cf.list_stack_resources(StackName=parent)["StackResourceSummaries"]
    }
    assert "Child" in resources, f"expected a Child resource, got {sorted(resources)}"
    assert resources["Child"]["ResourceType"] == "AWS::CloudFormation::Stack", resources["Child"]
    child_id = resources["Child"]["PhysicalResourceId"]
    assert ":stack/" in child_id, (
        f"a nested stack's PhysicalResourceId must be the child stack ARN, got {child_id!r}"
    )

    child_obj = _describe(cf, child_id)
    assert child_obj is not None, f"the child stack {child_id} must be describable in its own right"
    assert child_obj["StackStatus"] == "CREATE_COMPLETE", child_obj
    assert child_obj.get("ParentId") == parent_id, (
        f"the child's ParentId must be the parent StackId {parent_id!r}, got "
        f"{child_obj.get('ParentId')!r}"
    )
    assert child_obj.get("RootId") == parent_id, (
        f"a one-level nesting must set RootId to the parent StackId, got "
        f"{child_obj.get('RootId')!r}"
    )
    assert parent_obj.get("ParentId") is None and parent_obj.get("RootId") is None, (
        f"a root stack must not report ParentId/RootId: {parent_obj.get('ParentId')!r} / "
        f"{parent_obj.get('RootId')!r}"
    )

    # Fn::GetAtt <Child>.Outputs.<Key> must cross the stack boundary.
    outputs = {o["OutputKey"]: o["OutputValue"] for o in parent_obj.get("Outputs", [])}
    assert outputs.get("FromChild") == f"{seed}-child", (
        f"Fn::GetAtt Child.Outputs.ChildValue must resolve the nested output, got "
        f"{outputs.get('FromChild')!r}"
    )
    assert outputs.get("ChildRef") == child_id, (
        f"Ref on a nested stack must return the child stack ARN, got {outputs.get('ChildRef')!r}"
    )
    assert _param_exists(ssm, child_param), (
        f"the nested stack's resource {child_param} must actually be provisioned"
    )

    # Cascade delete: removing the parent must remove the child and its resources.
    cf.delete_stack(StackName=parent)
    # A deleted stack stays addressable by ARN, so the child's terminal state is
    # observable rather than merely absent.
    deadline = time.monotonic() + 900
    while True:
        child_after = _describe(cf, child_id)
        if child_after is not None and child_after["StackStatus"] == "DELETE_COMPLETE":
            break
        assert time.monotonic() < deadline, (
            f"the child stack was not cascade-deleted within 900s (last="
            f"{None if child_after is None else child_after['StackStatus']!r})"
        )
        time.sleep(5)

    # The child reaches DELETE_COMPLETE while the parent is still DELETE_IN_PROGRESS, so the
    # parent's own terminal state has to be waited for.
    parent_after = _wait_terminal(cf, parent_id)
    assert parent_after["StackStatus"] == "DELETE_COMPLETE", (
        f"the parent stack must reach DELETE_COMPLETE, got {parent_after['StackStatus']!r}: "
        f"{parent_after.get('StackStatusReason')!r}"
    )

    # A deleted stack is unreachable by NAME but still describable by StackId.
    name_code, name_msg = _describe_error(cf, parent)
    assert name_code == "ValidationError", (
        f"DescribeStacks on the deleted parent's NAME must be ValidationError, got {name_code!r}"
    )
    assert name_msg == f"Stack with id {parent} does not exist", (
        f"the refusal must name the stack it could not find: {name_msg!r}"
    )
    by_id = cf.describe_stacks(StackName=parent_id)["Stacks"][0]
    assert by_id["StackStatus"] == "DELETE_COMPLETE", by_id

    assert not _param_exists(ssm, child_param), (
        f"the nested stack's resource {child_param} must be destroyed by the cascade delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""cfn-nested-three-level-grandchild-update-failure-rolls-back-every-level."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-nested-three-level-grandchild-update-failure-rolls-back-every-level"
GROUP = "nested-stacks-rejected"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _stack(cf, name):
    return cf.describe_stacks(StackName=name)["Stacks"][0]


def _wait_terminal(cf, name, *, timeout_s=600.0, interval_s=5.0):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _stack(cf, name)
        if stack["StackStatus"] in _TERMINAL:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s "
                f"(last={stack['StackStatus']!r})"
            )
        time.sleep(interval_s)


def _bucket(ctx, s3):
    name = ctx.unique_name("sim2real-cfn-nest3-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _grandchild_template(*, fail: bool) -> str:
    """The SSM parameter; ``fail`` adds a wait condition that always times out."""
    resources = {
        "Param": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {
                "Name": {"Ref": "ParamName"},
                "Type": "String",
                "Value": {"Fn::Sub": "${Seed}-grand"},
            },
        },
    }
    if fail:
        resources["Handle"] = {"Type": "AWS::CloudFormation::WaitConditionHandle"}
        resources["Fast"] = {
            "Type": "AWS::CloudFormation::WaitCondition",
            "DependsOn": "Param",
            "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "1", "Count": 1},
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Seed": {"Type": "String"}, "ParamName": {"Type": "String"}},
        "Resources": resources,
    })


def _child_template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Seed": {"Type": "String"},
            "ParamName": {"Type": "String"},
            "GrandUrl": {"Type": "String"},
        },
        "Resources": {
            "Grandchild": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {
                    "TemplateURL": {"Ref": "GrandUrl"},
                    "Parameters": {"Seed": {"Ref": "Seed"}, "ParamName": {"Ref": "ParamName"}},
                },
            },
        },
    })


def _root_template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Seed": {"Type": "String"},
            "ParamName": {"Type": "String"},
            "ChildUrl": {"Type": "String"},
            "GrandUrl": {"Type": "String"},
        },
        "Resources": {
            "Child": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {
                    "TemplateURL": {"Ref": "ChildUrl"},
                    "Parameters": {
                        "Seed": {"Ref": "Seed"},
                        "ParamName": {"Ref": "ParamName"},
                        "GrandUrl": {"Ref": "GrandUrl"},
                    },
                },
            },
        },
    })


def _url(region: str, bucket: str, key: str) -> str:
    return f"https://s3.{region}.amazonaws.com/{bucket}/{key}"


def _delete_stack_and_wait(cf, stack_id, *, timeout_s=600.0, interval_s=5.0):
    """Delete the stack by id and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _stack(cf, stack_id)
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() >= deadline:
            raise RuntimeError(
                f"stack {stack_id} teardown ended {stack['StackStatus']!r}: "
                f"{stack.get('StackStatusReason')!r}"
            )
        time.sleep(interval_s)


def _param_value(ssm, name):
    """The SSM parameter's current Value, or None when it does not exist."""
    try:
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ParameterNotFound":
            return None
        raise


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
    "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A 3-level nesting sets the grandchild's ParentId to the child and RootId to the root;
    a failing update at the grandchild rolls every level back to UPDATE_ROLLBACK_COMPLETE and
    leaves its SSM parameter at the pre-update value, read through SSM's own API.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-nested-stacks.html
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    bucket = _bucket(ctx, s3)

    for key, body in (
        ("grand-v1.json", _grandchild_template(fail=False)),
        ("grand-v2.json", _grandchild_template(fail=True)),
        ("child.json", _child_template()),
    ):
        s3.put_object(Bucket=bucket, Key=key, Body=body.encode())
        ctx.on_cleanup(lambda k=key: s3.delete_object(Bucket=bucket, Key=k))

    child_url = _url(ctx.region, bucket, "child.json")
    grand_v1_url = _url(ctx.region, bucket, "grand-v1.json")
    grand_v2_url = _url(ctx.region, bucket, "grand-v2.json")
    param_name = "/" + ctx.unique_name("sim2real-cfn-nest3-p-")

    root_name = ctx.unique_name("sim2real-cfn-nest3-root-")
    root_id = cf.create_stack(
        StackName=root_name,
        TemplateBody=_root_template(),
        Parameters=[
            {"ParameterKey": "Seed", "ParameterValue": "sim2real-v1"},
            {"ParameterKey": "ParamName", "ParameterValue": param_name},
            {"ParameterKey": "ChildUrl", "ParameterValue": child_url},
            {"ParameterKey": "GrandUrl", "ParameterValue": grand_v1_url},
        ],
        Tags=_TAGS,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, root_id))

    root = _wait_terminal(cf, root_id)
    assert root["StackStatus"] == "CREATE_COMPLETE", (
        f"the root must reach CREATE_COMPLETE, got {root['StackStatus']!r}: "
        f"{root.get('StackStatusReason')!r}"
    )
    assert root.get("ParentId") is None and root.get("RootId") is None, (
        f"a root stack reports no ParentId/RootId, got "
        f"{root.get('ParentId')!r} / {root.get('RootId')!r}"
    )

    child_id = cf.describe_stack_resource(StackName=root_id, LogicalResourceId="Child")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    child = _stack(cf, child_id)
    assert child["StackStatus"] == "CREATE_COMPLETE", child
    assert child.get("ParentId") == root_id, (
        f"the child's ParentId must name the root {root_id!r}, got {child.get('ParentId')!r}"
    )
    assert child.get("RootId") == root_id, (
        f"the child's RootId must name the root {root_id!r}, got {child.get('RootId')!r}"
    )

    grandchild_id = cf.describe_stack_resource(StackName=child_id, LogicalResourceId="Grandchild")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    grandchild = _stack(cf, grandchild_id)
    assert grandchild["StackStatus"] == "CREATE_COMPLETE", grandchild
    assert grandchild.get("ParentId") == child_id, (
        f"the grandchild's ParentId must name the CHILD {child_id!r} (not the root), got "
        f"{grandchild.get('ParentId')!r}"
    )
    assert grandchild.get("RootId") == root_id, (
        f"the grandchild's RootId must name the ROOT {root_id!r} (not the child), got "
        f"{grandchild.get('RootId')!r}"
    )

    before = _param_value(ssm, param_name)
    assert before == "sim2real-v1-grand", (
        f"the grandchild must provision its SSM parameter from the Seed it was passed, "
        f"got {before!r} via SSM's own GetParameter"
    )

    # An update that fails deep inside the grandchild must roll back every level above it, and
    # the grandchild's own resource must settle back to its pre-update value.
    cf.update_stack(
        StackName=root_id,
        TemplateBody=_root_template(),
        Parameters=[
            {"ParameterKey": "Seed", "ParameterValue": "sim2real-v2"},
            {"ParameterKey": "ParamName", "ParameterValue": param_name},
            {"ParameterKey": "ChildUrl", "ParameterValue": child_url},
            {"ParameterKey": "GrandUrl", "ParameterValue": grand_v2_url},
        ],
    )
    root_after = _wait_terminal(cf, root_id)
    assert root_after["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"the root must roll back to UPDATE_ROLLBACK_COMPLETE, got "
        f"{root_after['StackStatus']!r}: {root_after.get('StackStatusReason')!r}"
    )
    child_after = _wait_terminal(cf, child_id)
    assert child_after["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"the child must roll back to UPDATE_ROLLBACK_COMPLETE, got "
        f"{child_after['StackStatus']!r}: {child_after.get('StackStatusReason')!r}"
    )
    grandchild_after = _wait_terminal(cf, grandchild_id)
    assert grandchild_after["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"the grandchild must roll back to UPDATE_ROLLBACK_COMPLETE, got "
        f"{grandchild_after['StackStatus']!r}: {grandchild_after.get('StackStatusReason')!r}"
    )

    after = _param_value(ssm, param_name)
    assert after == "sim2real-v1-grand", (
        f"SSM's own GetParameter must still show the pre-update value 'sim2real-v1-grand' after "
        f"the rollback, got {after!r} — a value of 'sim2real-v2-grand' would mean the failed "
        f"update's change to a resource three levels down was not reverted"
    )

    leftover = [
        r["LogicalResourceId"]
        for r in cf.describe_stack_resources(StackName=grandchild_id)["StackResources"]
        if r["LogicalResourceId"] in ("Handle", "Fast")
    ]
    assert leftover == [], (
        f"the rolled-back grandchild must not retain the failed update's new resources: {leftover!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

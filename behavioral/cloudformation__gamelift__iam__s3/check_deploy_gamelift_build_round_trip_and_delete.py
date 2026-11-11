"""deploy-gamelift-build-round-trip-and-delete."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-gamelift-build-round-trip-and-delete"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "gamelift", "iam", "s3"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_KEY = "build.zip"
_OPERATING_SYSTEM = "AMAZON_LINUX_2023"
_SERVER_SDK_VERSION = "5.0.0"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "gamelift.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}
_POLICY_NAME = "BuildResourceIAMPolicy"


def _policy(object_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
            "Resource": object_arn,
        }],
    }


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("server.sh", "#!/bin/sh\nexit 0\n")
    return buf.getvalue()


def _template(bucket: str, role_name: str, build_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "BuildRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": _TRUST,
                    "Policies": [{
                        "PolicyName": _POLICY_NAME,
                        "PolicyDocument": _policy(
                            {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/{_KEY}"}),
                    }],
                },
            },
            "Build": {
                "Type": "AWS::GameLift::Build",
                "Properties": {
                    "Name": build_name,
                    "OperatingSystem": _OPERATING_SYSTEM,
                    "ServerSdkVersion": _SERVER_SDK_VERSION,
                    "StorageLocation": {
                        "Bucket": bucket, "Key": _KEY,
                        "RoleArn": {"Fn::GetAtt": ["BuildRole", "Arn"]},
                    },
                },
                "DependsOn": "BuildRole",
            },
        },
        "Outputs": {
            "BuildId": {"Value": {"Ref": "Build"}},
            "BuildArn": {"Value": {"Fn::GetAtt": ["Build", "BuildArn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["BuildRole", "Arn"]}},
        },
    })


def _build_ids_named(gl, name: str) -> list[str]:
    """The BuildId of every build called ``name``, read across all pages of ListBuilds."""
    ids: list[str] = []
    kwargs: dict = {}
    while True:
        page = gl.list_builds(**kwargs)
        ids += [b["BuildId"] for b in page.get("Builds", []) if b.get("Name") == name]
        if not page.get("NextToken"):
            return ids
        kwargs["NextToken"] = page["NextToken"]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Empty and delete the bucket; only its own NoSuchBucket means it was never created."""
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_build_terminal(gl, build_id: str, deadline_s: float = 240.0, poll_s: float = 5.0) -> dict:
    """Poll DescribeBuild until the build leaves status INITIALIZED."""
    deadline = time.monotonic() + deadline_s
    while True:
        build = gl.describe_build(BuildId=build_id)["Build"]
        if build["Status"] != "INITIALIZED":
            return build
        assert time.monotonic() < deadline, (
            f"build {build_id!r} still INITIALIZED after {deadline_s}s"
        )
        time.sleep(poll_s)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::GameLift::Build with an S3 StorageLocation and an IAM role
    GameLift assumes reaches READY with the declared Name, OperatingSystem and ServerSdkVersion,
    the role carries its trust and inline policy, and deleting the stack removes both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-gamelift-build.html
    """
    s3 = ctx.client("s3")
    gl = ctx.client("gamelift")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-glbuild-bkt-")
    bucket_kw = ({} if ctx.region == "us-east-1"
                 else {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.create_bucket(Bucket=bucket, **bucket_kw)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_zip_bytes())

    stack = ctx.unique_name("sim2real-glbuild-")
    role_name = ctx.unique_name("sim2real-glbuild-role-")
    build_name = ctx.unique_name("sim2real-glbuild-name-")

    stack_id = create_stack(ctx, cfn, stack, _template(bucket, role_name, build_name),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    build_id, build_arn = outputs["BuildId"], outputs["BuildArn"]

    named = _build_ids_named(gl, build_name)
    assert named == [build_id], (
        f"expected Ref Build to be the one BuildId GameLift lists for {build_name!r}, "
        f"Ref gave {build_id!r} and GameLift lists {named!r}"
    )

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == outputs["RoleArn"], (
        f"expected IAM role Arn {outputs['RoleArn']!r}, IAM reports {role['Arn']!r}"
    )
    assert role["AssumeRolePolicyDocument"] == _TRUST, (
        f"expected trust policy {_TRUST!r}, IAM reports {role['AssumeRolePolicyDocument']!r}"
    )
    inline = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert inline == [_POLICY_NAME], f"expected inline policies [{_POLICY_NAME!r}], IAM reports {inline!r}"
    document = iam.get_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME)["PolicyDocument"]
    want_document = _policy(f"arn:{stack_id.split(':')[1]}:s3:::{bucket}/{_KEY}")
    assert document == want_document, (
        f"expected inline policy {want_document!r}, IAM reports {document!r}"
    )

    build = _wait_build_terminal(gl, build_id)
    assert build["Status"] == "READY", f"expected Build Status READY, GameLift reports {build['Status']!r}"
    assert build["BuildArn"] == build_arn, (
        f"expected BuildArn {build_arn!r}, GameLift reports {build['BuildArn']!r}"
    )
    assert build["BuildId"] == build_id, f"expected BuildId {build_id!r}, GameLift reports {build['BuildId']!r}"
    assert build["Name"] == build_name, f"expected Name {build_name!r}, GameLift reports {build['Name']!r}"
    assert build["ServerSdkVersion"] == _SERVER_SDK_VERSION, (
        f"expected ServerSdkVersion {_SERVER_SDK_VERSION!r}, GameLift reports {build['ServerSdkVersion']!r}"
    )
    assert build["OperatingSystem"] == _OPERATING_SYSTEM, (
        f"expected OperatingSystem {_OPERATING_SYSTEM!r}, GameLift reports {build['OperatingSystem']!r}"
    )

    delete_stack(cfn, stack_id)

    build_gone = ("NotFoundException", f"Build ({build_id}) not found")
    expect_error(lambda: gl.describe_build(BuildId=build_id), *build_gone)

    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

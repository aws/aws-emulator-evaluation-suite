"""deploy-s3files-filesystem-unversioned-bucket-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-s3files-filesystem-unversioned-bucket-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3files"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

def _resources(marker: str, bucket: str, versioning: str = "Enabled") -> dict:
    """A versioned bucket, a role S3 Files assumes scoped to that bucket, and a file system."""
    t = [{"Key": "sim2real-s3files", "Value": marker}]
    bucket_arn = {"Fn::GetAtt": ["Bucket", "Arn"]}
    return {
        "Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {"BucketName": bucket,
                           "VersioningConfiguration": {"Status": versioning}, "Tags": t},
        },
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "elasticfilesystem.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "allow-own-bucket",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": [bucket_arn,
                                         {"Fn::Sub": ["${Arn}/*", {"Arn": bucket_arn}]}],
                        }],
                    },
                }],
                "Tags": t,
            },
        },
        "FS": {
            "Type": "AWS::S3Files::FileSystem",
            "Properties": {
                "Bucket": bucket_arn,
                "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                "Tags": t,
            },
        },
    }


_FS_OUTPUTS = {
    "FileSystemRef": {"Value": {"Ref": "FS"}},
    "FileSystemId": {"Value": {"Fn::GetAtt": ["FS", "FileSystemId"]}},
    "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
    "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
}


def _template(resources: dict, outputs: dict) -> str:
    body = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}
    if outputs:
        body["Outputs"] = outputs
    return json.dumps(body)


def _bucket_name(ctx) -> str:
    return ctx.unique_name("sim2real-s3files-").lower()[:63]


def _listed_fs(s3files, bucket_arn: str) -> list:
    """The file systems S3 Files pages out for ``bucket_arn``."""
    return paginate(s3files, "list_file_systems", "fileSystems", bucket=bucket_arn)


_REJECTED = (
    "Your bucket must have versioning enabled to create a file system. "
    "(Service: S3Files, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::S3Files::FileSystem over a bucket whose versioning is Suspended is
    rejected by S3 Files with its exact error and no file system exists for that bucket, while the
    same template with versioning Enabled creates one over its bucket and role.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3files-filesystem.html
    """
    s3files = ctx.client("s3files")
    cfn = ctx.client("cloudformation")
    bad_marker = ctx.unique_name("sim2real-s3filesfsbad-")
    good_marker = ctx.unique_name("sim2real-s3filesfsgood-")
    bad_bucket = _bucket_name(ctx)

    bad_id = create_stack(ctx, cfn, bad_marker,
                          _template(_resources(bad_marker, bad_bucket, "Suspended"), {}),
                          Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "FS"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through S3 Files, by the bucket the file system would have used, before
    # any delete.
    partition = bad_id.split(":")[1]
    left = _listed_fs(s3files, f"arn:{partition}:s3:::{bad_bucket}")
    assert left == [], f"S3 Files lists a file system over the rejected bucket: {left!r}"

    # Positive control: the same template, versioning given the enabled value.
    good_id = create_stack(ctx, cfn, good_marker,
                           _template(_resources(good_marker, _bucket_name(ctx)), _FS_OUTPUTS),
                           Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    listed = _listed_fs(s3files, out["BucketArn"])
    got = [(f["fileSystemId"], f["status"], f["bucket"], f["roleArn"]) for f in listed]
    assert got == [(out["FileSystemId"], "available", out["BucketArn"], out["RoleArn"])], (
        f"control file system over its bucket {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

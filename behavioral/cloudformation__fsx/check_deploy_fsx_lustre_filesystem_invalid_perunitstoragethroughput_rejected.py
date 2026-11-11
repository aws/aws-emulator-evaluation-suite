"""deploy-fsx-lustre-filesystem-invalid-perunitstoragethroughput-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-fsx-lustre-filesystem-invalid-perunitstoragethroughput-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "fsx"]

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


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.125.0.0/16"
_SUBNET_CIDR = "10.125.1.0/24"
_BAD_THROUGHPUT = 999
_GOOD_THROUGHPUT = 125
# A Lustre file system takes most of the run to create; the control's wait gets this long.
_FS_WAIT_S = 1500.0
_REJECTED = (
    'Resource handler returned message: "Invalid Lustre deployment configuration: The '
    "storage throughput (MB/s/TiB) value should be one of [125,250,500,1000]. (Service: "
    "AmazonFSx; Status Code: 400; Error Code: InvalidPerUnitStorageThroughput; Request ID: "
    '<id>; Proxy: null)" (RequestToken: <token>)'
)


def _template(tag_value: str, az: str, throughput: int) -> str:
    t = [{"Key": "sim2real-fsx", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                               "AvailabilityZone": az, "Tags": t},
            },
            "FileSystem": {
                "Type": "AWS::FSx::FileSystem",
                "Properties": {
                    "FileSystemType": "LUSTRE",
                    "FileSystemTypeVersion": "2.12",
                    "StorageCapacity": 1200,
                    "SubnetIds": [{"Ref": "Subnet"}],
                    "LustreConfiguration": {
                        "DeploymentType": "PERSISTENT_2",
                        "PerUnitStorageThroughput": throughput,
                    },
                    "Tags": t,
                },
            },
        },
        "Outputs": {"FileSystemId": {"Value": {"Ref": "FileSystem"}}},
    })


def _tagged(fsx, value: str) -> list[dict]:
    """Every file system (all pages) carrying the run's sim2real-fsx tag value."""
    return [f for f in paginate(fsx, "describe_file_systems", "FileSystems")
            if {"Key": "sim2real-fsx", "Value": value} in f.get("Tags", [])]


def _usable_az(ec2) -> str:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Lustre PERSISTENT_2 file system with an invalid throughput fails and rolls back.

    FSx refuses PerUnitStorageThroughput 999 and lists no file system for the stack, while the
    same template with 125 deploys a file system FSx reads back with 125.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-fsx-filesystem.html
    """
    ec2 = ctx.client("ec2")
    fsx = ctx.client("fsx")
    cfn = ctx.client("cloudformation")
    az = _usable_az(ec2)
    good = ctx.unique_name("sim2real-fsxthr-good-")
    bad = ctx.unique_name("sim2real-fsxthr-bad-")

    # The control starts first and is waited on last: the file system dominates the run.
    good_id = create_stack(ctx, cfn, good, _template(good, az, _GOOD_THROUGHPUT))
    bad_id = create_stack(ctx, cfn, bad, _template(bad, az, _BAD_THROUGHPUT))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "FileSystem")
    got = masked(reason, ctx.account, bad)
    assert got == _REJECTED, f"FileSystem reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through FSx, by the run's tag, BEFORE this check deletes anything.
    listed = _tagged(fsx, bad)
    assert listed == [], f"FSx lists a file system for the rolled-back stack: {listed!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id, timeout_s=_FS_WAIT_S)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    fs_ref = stack_outputs(cfn, good_id)["FileSystemId"]
    got = [(f["FileSystemId"], f["LustreConfiguration"]["DeploymentType"],
            f["LustreConfiguration"]["PerUnitStorageThroughput"]) for f in _tagged(fsx, good)]
    assert got == [(fs_ref, "PERSISTENT_2", _GOOD_THROUGHPUT)], f"control file system {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

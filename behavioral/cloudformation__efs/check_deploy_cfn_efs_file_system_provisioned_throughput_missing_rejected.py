"""deploy-cfn-efs-file-system-provisioned-throughput-missing-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-efs-file-system-provisioned-throughput-missing-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "efs"]

_RUN_TAG = "sim2real-run"

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _template(throughput_mode: str, run_token: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Fs": {
                "Type": "AWS::EFS::FileSystem",
                "Properties": {
                    "ThroughputMode": throughput_mode,
                    "FileSystemTags": [
                        {"Key": "sim2real", "Value": CHECK},
                        {"Key": _RUN_TAG, "Value": run_token},
                    ],
                },
            }
        },
    })


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::EFS::FileSystem with ThroughputMode provisioned but no ProvisionedThroughputInMibps
    fails with EFS's error and creates no file system; the same template in bursting mode deploys."""
    cfn = ctx.client("cloudformation")
    efs = ctx.client("efs")

    run_token = ctx.unique_name("sim2real-behav-efsrun-")
    good_stack = ctx.unique_name("sim2real-behav-stack-ok-")
    bad_stack = ctx.unique_name("sim2real-behav-stack-bad-")

    # Positive control: the identical template in bursting mode, through CloudFormation.
    _create(ctx, cfn, good_stack, _template("bursting", run_token))
    status = _poll_until_terminal(cfn, good_stack, timeout_s=240.0)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    good_fs_id = cfn.describe_stack_resource(StackName=good_stack, LogicalResourceId="Fs")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    good_fs = efs.describe_file_systems(FileSystemId=good_fs_id)["FileSystems"][0]
    assert good_fs["ThroughputMode"] == "bursting", (
        f"positive control: expected ThroughputMode bursting, got {good_fs['ThroughputMode']!r}"
    )

    # The one thing broken: provisioned mode without the throughput it requires.
    _create(ctx, cfn, bad_stack, _template("provisioned", run_token))
    status = _poll_until_terminal(cfn, bad_stack, timeout_s=240.0)
    assert status == "CREATE_FAILED", f"expected stack status CREATE_FAILED, got {status!r}"
    reason = _failed_reason(cfn, bad_stack, "Fs")
    match = _REASON.match(reason)
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        "Provisioned throughput must be set for file systems that use provisioned throughput mode.",
        "Efs",
        "400",
        "InvalidRequest",
    )
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    # Effect-absent through EFS itself: only the control's file system carries this run's tag.
    tagged = _tagged_file_systems(efs, run_token)
    assert tagged == [good_fs_id], (
        f"expected only the control file system {good_fs_id!r} to carry this run's tag, got {tagged!r}"
    )

    for stack_name in (bad_stack, good_stack):
        _delete_stack(cfn, stack_name)
        got = _error(lambda stack_name=stack_name: cfn.describe_stacks(StackName=stack_name))
        assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
            f"DescribeStacks after the delete of {stack_name}: {got!r}"
        )
    got = _error(lambda: efs.describe_file_systems(FileSystemId=good_fs_id))
    assert got == ("FileSystemNotFound", f"File system '{good_fs_id}' does not exist."), (
        f"the control file system after its stack delete: {got!r}"
    )


def _tagged_file_systems(efs, run_token: str) -> list[str]:
    """Ids of every file system tagged with this run's token."""
    found = []
    for page in efs.get_paginator("describe_file_systems").paginate():
        for fs in page["FileSystems"]:
            if {"Key": _RUN_TAG, "Value": run_token} in fs.get("Tags", []):
                found.append(fs["FileSystemId"])
    return sorted(found)


def _create(ctx, cfn, stack_name: str, body: str) -> None:
    """CreateStack with its delete registered at once."""
    cfn.create_stack(
        StackName=stack_name, TemplateBody=body, DisableRollback=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))


def _poll_until_terminal(cfn, stack_name: str, *, timeout_s: float) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status in {timeout_s}s, last {status!r}")


def _failed_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single CREATE_FAILED event."""
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        events.extend(page["StackEvents"])
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""cfn-ec2-launch-template-in-place-new-version-retained-replacement-then-not-found."""

from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-launch-template-in-place-new-version-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a new template or version can briefly answer NotFound.
_PROPAGATE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
FIRST_TYPE = "t3.nano"
SECOND_TYPE = "t3.micro"
USER_DATA = base64.b64encode(b"#!/bin/bash\necho launch-template-check\n").decode()

#: EC2's answer to a launch request that would have run, sent with DryRun.
_DRY_RUN_OK = ("DryRunOperation", "Request would have succeeded, but DryRun flag is set.")
#: EC2's refusal of a launch template id that no longer exists.
_NOT_FOUND = (
    "InvalidLaunchTemplateId.NotFound",
    "At least one of the launch templates specified in the request does not exist.",
)


#: DescribeLaunchTemplates of a template name that does not exist.
_NAME_NOT_FOUND = (
    "InvalidLaunchTemplateName.NotFoundException",
    "At least one of the launch templates specified in the request does not exist.",
)


def _template(name: str, instance_type: str, ami: str | None = None) -> str:
    """The stack template; *ami* pins the image the create resolved, so updates never move it."""
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Ami": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": AMI_PARAMETER,
            },
        },
    }
    if ami is not None:
        del body["Parameters"]
    return json.dumps(
        {
            **body,
            "Resources": {
                "Lt": {
                    "Type": "AWS::EC2::LaunchTemplate",
                    # LaunchTemplateName is create-only, so changing it replaces the template.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "LaunchTemplateName": name,
                        "LaunchTemplateData": {
                            "ImageId": {"Ref": "Ami"} if ami is None else ami,
                            "InstanceType": instance_type,
                            "UserData": USER_DATA,
                        },
                    },
                },
            },
            "Outputs": {
                "LaunchTemplateId": {"Value": {"Fn::GetAtt": ["Lt", "LaunchTemplateId"]}},
                "DefaultVersionNumber": {"Value": {"Fn::GetAtt": ["Lt", "DefaultVersionNumber"]}},
                "LatestVersionNumber": {"Value": {"Fn::GetAtt": ["Lt", "LatestVersionNumber"]}},
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A LaunchTemplateData change adds version 2 and keeps version 1 as the default.

    Each listed version holds the templated data and launches under DryRun; a LaunchTemplateName
    change under UpdateReplacePolicy Retain keeps the old template; delete: NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-launchtemplate.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    first = ctx.unique_name("sim2real-cfnlt-a-")
    second = ctx.unique_name("sim2real-cfnlt-b-")
    stack_name = ctx.unique_name("sim2real-cfnlt-stack-")
    subnet = _launchable_subnet(ctx, ec2)
    ref = {"stack": stack_name}

    # The replaced template is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_launch_template(ec2, first))
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))

    # ---- 1. create: CloudFormation's view, EC2's view, and a dry-run launch
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, FIRST_TYPE), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first_id = _physical_ids(cfn, ref["stack"])["Lt"]
    assert first_id.startswith("lt-"), f"the physical id {first_id!r} must be the template's id"
    ami = next(p["ResolvedValue"] for p in stack["Parameters"] if p["ParameterKey"] == "Ami")
    assert ami.startswith("ami-"), f"the Ami parameter resolved to {ami!r}"
    assert _outputs(stack) == _version_outputs(first_id, 1, 1), f"outputs {_outputs(stack)!r}"
    _assert_template(ctx, ec2, first_id, first, default=1, latest=1)
    data_1 = {"ImageId": ami, "InstanceType": FIRST_TYPE, "UserData": USER_DATA}
    _assert_versions(ctx, ec2, first_id, {1: (True, data_1)})
    _assert_launches(ctx, ec2, first_id, "$Default", subnet)

    # ---- 2. in-place: new LaunchTemplateData is a new version; the default stays version 1
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(first, SECOND_TYPE, ami), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Lt"] == first_id, (
        "an in-place update keeps the template"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Lt"), first_id, "Lt")
    assert _outputs(stack) == _version_outputs(first_id, 1, 2), (
        f"outputs after the in-place update {_outputs(stack)!r}"
    )
    _assert_template(ctx, ec2, first_id, first, default=1, latest=2)
    data_2 = {"ImageId": ami, "InstanceType": SECOND_TYPE, "UserData": USER_DATA}
    _assert_versions(ctx, ec2, first_id, {1: (True, data_1), 2: (False, data_2)})
    _assert_launches(ctx, ec2, first_id, "$Default", subnet)
    _assert_launches(ctx, ec2, first_id, "$Latest", subnet)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new template, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second, SECOND_TYPE, ami), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_id = _physical_ids(cfn, ref["stack"])["Lt"]
    assert second_id != first_id, f"the replacement must be a new template, still {first_id!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Lt"), first_id, second_id, "Lt"
    )
    assert _outputs(stack) == _version_outputs(second_id, 1, 1), (
        f"outputs after the replacement {_outputs(stack)!r}"
    )
    _assert_template(ctx, ec2, second_id, second, default=1, latest=1)
    _assert_versions(ctx, ec2, second_id, {1: (True, data_2)})
    _assert_launches(ctx, ec2, second_id, "$Default", subnet)
    _assert_template(ctx, ec2, first_id, first, default=1, latest=2)
    _assert_versions(ctx, ec2, first_id, {1: (True, data_1), 2: (False, data_2)})

    # ---- 4. delete: EC2 no longer knows the stack's template; the retained one stays
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: ec2.describe_launch_templates(LaunchTemplateIds=[second_id]),
        _NOT_FOUND[0],
        f"launch template {second_id}",
    )
    code, message = got
    assert (code, message) == _NOT_FOUND, f"DescribeLaunchTemplates after the delete: {got!r}"
    _assert_template(ctx, ec2, first_id, first, default=1, latest=2)


def _version_outputs(lt_id: str, default: int, latest: int) -> dict[str, str]:
    return {
        "LaunchTemplateId": lt_id,
        "DefaultVersionNumber": str(default),
        "LatestVersionNumber": str(latest),
    }


def _launchable_subnet(ctx, ec2) -> str:
    """A shared-network subnet whose zone offers both instance types the template names."""
    network = ctx.network()
    offered = None
    for instance_type in (FIRST_TYPE, SECOND_TYPE):
        zones = {
            o["Location"]
            for o in ec2.describe_instance_type_offerings(
                LocationType="availability-zone",
                Filters=[{"Name": "instance-type", "Values": [instance_type]}],
            )["InstanceTypeOfferings"]
        }
        offered = zones if offered is None else offered & zones
    usable = [z for z in network.availability_zones if z in offered]
    assert usable, (
        f"no zone of {network.availability_zones!r} offers {FIRST_TYPE} and {SECOND_TYPE}"
    )
    return network.subnets[usable[0]]


def _assert_template(ctx, ec2, lt_id: str, name: str, *, default: int, latest: int) -> None:
    """DescribeLaunchTemplates reports the template's name and version numbers exactly."""

    def read():
        lt = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
        got = (lt["LaunchTemplateId"], lt["LaunchTemplateName"])
        return got + (lt["DefaultVersionNumber"], lt["LatestVersionNumber"])

    want = (lt_id, name, default, latest)
    got = _poll(ctx, read, want, f"DescribeLaunchTemplates {lt_id} (id, name, default, latest)")
    assert got == want, f"DescribeLaunchTemplates {lt_id}: {got!r}, expected {want!r}"


def _assert_versions(ctx, ec2, lt_id: str, want: dict[int, tuple[bool, dict]]) -> None:
    """Every version EC2 lists: number -> (DefaultVersion, LaunchTemplateData), exactly."""

    def read():
        versions = []
        for page in ec2.get_paginator("describe_launch_template_versions").paginate(
            LaunchTemplateId=lt_id
        ):
            versions.extend(page["LaunchTemplateVersions"])
        return {
            v["VersionNumber"]: (v["DefaultVersion"], v["LaunchTemplateData"]) for v in versions
        }

    got = _poll(ctx, read, want, f"DescribeLaunchTemplateVersions {lt_id}")
    assert got == want, f"DescribeLaunchTemplateVersions {lt_id}: {got!r}, expected {want!r}"


def _assert_launches(ctx, ec2, lt_id: str, version: str, subnet: str) -> None:
    """RunInstances from the template version, sent with DryRun, would have launched.

    Polled: a version EC2 has just created can briefly be unknown to RunInstances.
    """

    def read():
        try:
            ec2.run_instances(
                DryRun=True,
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet,
                LaunchTemplate={"LaunchTemplateId": lt_id, "Version": version},
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return "launched without DryRun refusing", None

    code, message = _poll(ctx, read, _DRY_RUN_OK, f"a dry-run launch of {lt_id} {version}")
    assert (code, message) == _DRY_RUN_OK, f"a dry-run launch of {lt_id} {version}: {code!r}"


def _delete_launch_template(ec2, name: str) -> None:
    """Delete the template by name; a refusal passes only on DescribeLaunchTemplates' not-found."""
    try:
        ec2.delete_launch_template(LaunchTemplateName=name)
    except ClientError as exc:
        try:
            ec2.describe_launch_templates(LaunchTemplateNames=[name])
        except ClientError as gone:
            err = gone.response["Error"]
            if (err["Code"], err.get("Message")) == _NAME_NOT_FOUND:
                return
            raise exc from gone
        raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ``ctx=None`` and waits the full
    cap, since the body's deadline does not bound the cleanup.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Registered with ``ctx=None`` so its waits take their full caps after the body's deadline.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


def _poll(ctx, read, want, what: str):
    """Poll ``read()`` until it returns *want* (EC2 reads are eventually consistent).

    A ClientError while polling is retried; the last answer is named when the cap ends.
    """
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        try:
            got = read()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = ("error", err.get("Code"), err.get("Message"))
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {what} showed {want!r}")
            raise AssertionError(f"{what}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

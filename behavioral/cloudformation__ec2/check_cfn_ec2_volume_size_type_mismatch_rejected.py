"""cfn-ec2-volume-size-type-mismatch-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-ec2-volume-size-type-mismatch-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}
_VALIDATION_REASON = "Property [Size] expected type: Integer, found: String"
_VALIDATION_PATH = "/Resources/V/Properties/Size"


def _template(az: str, size, run: str) -> str:
    return json.dumps({
        "Resources": {
            "V": {
                "Type": "AWS::EC2::Volume",
                "Properties": {
                    "AvailabilityZone": az,
                    "VolumeType": "gp3",
                    "Size": size,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real-run", "Value": run}],
                },
            },
        },
    })


def _volumes_tagged(ec2, run: str) -> list[dict]:
    """Every volume carrying ``sim2real-run=<run>``, across all pages."""
    pages = ec2.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "tag:sim2real-run", "Values": [run]}])
    return [v for page in pages for v in page["Volumes"]]


def _wait_terminal(cfn, name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _validation_errors(cfn, name: str) -> list[tuple]:
    """``(logical id, reason, path)`` of each VALIDATION_ERROR operation event for V."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "V"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


@tags(
    "axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A volume whose Size is a non-numeric string fails CloudFormation's pre-provisioning type
    check with its exact message and EC2 holds no volume tagged for that stack, while an Integer
    Size deploys and the volume reads back with every declared property.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    az = usable[0]

    # --- positive control: an Integer Size deploys ---
    good_stack = ctx.unique_name("sim2real-cfn-voltype-ok-")
    cfn.create_stack(StackName=good_stack, TemplateBody=_template(az, 1, good_stack))
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    good_physical = cfn.describe_stack_resources(StackName=good_stack, LogicalResourceId="V")[
        "StackResources"][0]["PhysicalResourceId"]
    good_volume = ec2.describe_volumes(VolumeIds=[good_physical])["Volumes"][0]
    assert good_volume["Size"] == 1, f"control volume size read back as {good_volume['Size']!r}"
    assert good_volume["VolumeType"] == "gp3", (
        f"control volume type read back as {good_volume['VolumeType']!r}, expected 'gp3'"
    )
    assert good_volume["AvailabilityZone"] == az, (
        f"control volume AZ read back as {good_volume['AvailabilityZone']!r}, expected {az!r}"
    )
    good_tags = {t["Key"]: t["Value"] for t in good_volume.get("Tags", []) if not t["Key"].startswith("aws:")}
    assert good_tags == {"sim2real": CHECK, "sim2real-run": good_stack}, (
        f"control volume tags read back as {good_tags!r}"
    )
    tagged = [v["VolumeId"] for v in _volumes_tagged(ec2, good_stack)]
    assert tagged == [good_physical], (
        f"the run-tag filter should find exactly the control volume, found {len(tagged)} volume(s)"
    )

    # --- negative: a non-numeric string for Size ---
    bad_stack = ctx.unique_name("sim2real-cfn-voltype-bad-")
    cfn.create_stack(StackName=bad_stack, TemplateBody=_template(az, "not-a-number", bad_stack))
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    status = _wait_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"non-numeric Size: expected ROLLBACK_COMPLETE, got {status!r}"
    found = _validation_errors(cfn, bad_stack)
    assert found == [("V", _VALIDATION_REASON, _VALIDATION_PATH)], (
        f"non-numeric Size: validation errors expected a single ({_VALIDATION_REASON!r}, "
        f"{_VALIDATION_PATH!r}), got {found!r}"
    )
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    logical_ids = sorted(r["LogicalResourceId"] for r in resources)
    assert logical_ids == [], (
        f"non-numeric Size: a stack rejected before provisioning must list no resources, got {logical_ids!r}"
    )
    leaked = [v["VolumeId"] for v in _volumes_tagged(ec2, bad_stack)]
    assert leaked == [], (
        f"non-numeric Size: EC2 holds {len(leaked)} volume(s) tagged for the rejected stack"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

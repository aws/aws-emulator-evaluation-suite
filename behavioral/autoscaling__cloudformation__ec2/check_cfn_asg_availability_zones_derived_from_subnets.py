"""cfn-asg-availability-zones-derived-from-subnets."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-asg-availability-zones-derived-from-subnets"

GROUP = "deployment-order"

SERVICES = ["autoscaling", "cloudformation", "ec2"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Auto Scaling group deployed with only VPCZoneIdentifier must report the availability
    zones EC2 reports for those subnets, launch nothing at zero capacity, and its launch template
    must resolve to the AMI and instance type the stack passed in.
    """
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")

    image_id = _latest_amazon_linux_ami(ec2)
    asg_name = _xname(ctx, "asg")
    launch_template_name = _xname(ctx, "lt")

    result = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / "asg-zero-desired.yaml").read_text(),
        parameters={
            "ImageId": image_id,
            "LaunchTemplateName": launch_template_name,
            "AsgName": asg_name,
        },
        timeout_s=900.0,
    )
    outputs = _outputs(result)
    assert outputs["AsgNameOut"] == asg_name, outputs

    # Registered AFTER the deploy so LIFO runs it BEFORE the stack delete: an Auto Scaling group
    # that somehow acquired capacity must be scaled to zero and force-deleted before
    # CloudFormation tries to remove the subnets it sits in.
    ctx.on_cleanup(lambda: _force_delete_asg_if_present(autoscaling, asg_name))

    group = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"],
        lambda groups: bool(groups),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"auto scaling group {asg_name} visible",
    )[0]

    # 1. The subnets CloudFormation created are the ones the group is attached to.
    subnet_ids = [outputs["SubnetAId"], outputs["SubnetBId"]]
    assert set(group["VPCZoneIdentifier"].split(",")) == set(subnet_ids), (
        f"VPCZoneIdentifier is {group['VPCZoneIdentifier']!r}, expected the stack's subnets "
        f"{subnet_ids}"
    )

    # 2. The zones were DERIVED: nothing in the template names them.
    ec2_zones = {
        s["SubnetId"]: s["AvailabilityZone"]
        for s in ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]
    }
    assert len(set(ec2_zones.values())) == 2, ec2_zones
    assert set(group["AvailabilityZones"]) == set(ec2_zones.values()), (
        f"Auto Scaling reports zones {sorted(group['AvailabilityZones'])}; EC2 says those subnets "
        f"are in {sorted(set(ec2_zones.values()))}. AvailabilityZones must be derived from "
        "VPCZoneIdentifier."
    )
    for subnet in ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]:
        assert subnet["VpcId"] == outputs["VpcId"], subnet

    # 3. Capacity really is zero and nothing was launched (the stack is zero-capacity by design).
    assert (group["MinSize"], group["MaxSize"], group["DesiredCapacity"]) == (0, 1, 0), (
        f"capacity is {(group['MinSize'], group['MaxSize'], group['DesiredCapacity'])}, "
        "expected (0, 1, 0)"
    )
    assert group["Instances"] == [], (
        f"a DesiredCapacity 0 group must launch nothing, but reports {group['Instances']}"
    )
    reservations = ec2.describe_instances(
        Filters=[
            {"Name": "tag:aws:autoscaling:groupName", "Values": [asg_name]},
            {
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped"],
            },
        ]
    )["Reservations"]
    assert reservations == [], (
        f"EC2 reports instances for {asg_name}: {reservations}. Zero desired capacity must mean "
        "zero instances (this is also this archetype's cost-leak guard)."
    )

    # 4. The launch template linkage resolves all the way to the AMI.
    linked = group.get("LaunchTemplate") or group.get(
        "MixedInstancesPolicy", {}
    ).get("LaunchTemplate", {}).get("LaunchTemplateSpecification", {})
    assert linked.get("LaunchTemplateId") == outputs["LaunchTemplateId"], (
        f"the group points at launch template {linked!r}, the stack created "
        f"{outputs['LaunchTemplateId']!r}"
    )
    assert linked.get("LaunchTemplateName") == launch_template_name, linked
    assert linked.get("Version") == outputs["LaunchTemplateLatestVersion"], (
        f"the group is pinned to version {linked.get('Version')!r}, GetAtt "
        f"LatestVersionNumber returned {outputs['LaunchTemplateLatestVersion']!r}"
    )

    versions = ec2.describe_launch_template_versions(
        LaunchTemplateId=outputs["LaunchTemplateId"],
        Versions=[str(outputs["LaunchTemplateLatestVersion"])],
    )["LaunchTemplateVersions"]
    assert versions, outputs
    data = versions[0]["LaunchTemplateData"]
    assert data["ImageId"] == image_id, (
        f"launch template resolves to AMI {data['ImageId']!r}, the stack was given {image_id!r}"
    )
    assert data["InstanceType"] == "t3.micro", data


def _latest_amazon_linux_ami(ec2) -> str:
    """The newest Amazon-owned Amazon Linux 2023 x86_64 AMI in this region."""
    try:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2*-kernel-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
        )["Images"]
    except ClientError as exc:
        raise AssertionError(f"ec2:DescribeImages unavailable: {exc}") from exc
    if not images:
        raise AssertionError(
            "no Amazon Linux 2023 x86_64 AMI is available here, so a launch template cannot be "
            "given a valid ImageId"
        )
    newest = max(images, key=lambda i: i.get("CreationDate", ""))
    return newest["ImageId"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _force_delete_asg_if_present(autoscaling, asg_name: str) -> None:
    """Scale an Auto Scaling group to zero and force-delete it; absent is not an error.

    Belt-and-braces teardown for the resource class that leaks money if it is left running."""
    groups = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    if not groups:
        return
    deadline = time.monotonic() + 60
    while True:
        try:
            autoscaling.update_auto_scaling_group(
                AutoScalingGroupName=asg_name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "not found" in err.get("Message", ""):
                return
            if err.get("Code") not in ("ScalingActivityInProgress", "ResourceContention") or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(2)
    try:
        autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "ValidationError" or "not found" not in err.get("Message", ""):
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup).

    The deadline is a parameter."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=600.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

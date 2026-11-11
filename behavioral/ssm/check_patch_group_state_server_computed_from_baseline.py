"""patch-group-state-server-computed-from-baseline."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "patch-group-state-server-computed-from-baseline"
GROUP = "server-side"
SERVICES = ["ssm"]

_SSM_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePatchGroupState's Instances count reflects the SSM-managed nodes tagged into the patch
    group, computed server-side from managed-node inventory rather than echoed from a client call."""

    ssm = ctx.client("ssm")
    patch_group = ctx.unique_name("sim2real-pg-")
    unused_patch_group = ctx.unique_name("sim2real-pg-unused-")

    baseline_id = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-baseline-"),
        OperatingSystem="AMAZON_LINUX_2",
        ApprovalRules={
            "PatchRules": [
                {
                    "PatchFilterGroup": {
                        "PatchFilters": [{"Key": "PRODUCT", "Values": ["*"]}]
                    },
                    "ApproveAfterDays": 7,
                }
            ]
        },
    )["BaselineId"]
    ctx.on_cleanup(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))

    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: ssm.deregister_patch_baseline_for_patch_group(
            BaselineId=baseline_id, PatchGroup=patch_group
        )
    )

    # A dedicated managed node, launched with the patch-group tag, so the count reads only this
    # run's node. The group counts nodes that reported patch compliance, so the node scans first.
    instance_id = _launch_ssm_managed_instance(
        ctx, extra_tags=[{"Key": "Patch Group", "Value": patch_group}]
    )
    _scan_patches(ctx, ssm, instance_id)

    state = _poll_until_instances(ssm, patch_group, expected=1, timeout_s=180.0, ctx=ctx)
    assert state["Instances"] == 1, state

    # Control: a patch group name that was never registered/tagged has no managed nodes in it.
    control_state = ssm.describe_patch_group_state(PatchGroup=unused_patch_group)
    assert control_state["Instances"] == 0, control_state


def _scan_patches(ctx, ssm, instance_id: str, timeout_s: float = 480.0) -> None:
    """Run AWS-RunPatchBaseline Operation=Scan on the node and wait for the invocation to end."""
    from botocore.exceptions import ClientError

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPatchBaseline",
        Parameters={"Operation": ["Scan"]},
    )["Command"]["CommandId"]
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 60.0))
    deadline = time.monotonic() + timeout_s
    invocation = {"Status": "Pending"}
    while time.monotonic() < deadline:
        try:
            invocation = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvocationDoesNotExist":
                raise
        if invocation["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
        time.sleep(2.0)
    else:
        left = ctx.time_left()
        if left is not None and left <= 66.0:
            raise TimeoutError("AWS-RunPatchBaseline scan: the run budget ended first; not graded")
        raise AssertionError(f"AWS-RunPatchBaseline scan never finished: {invocation}")
    assert invocation["Status"] == "Success", invocation


def _poll_until_instances(ssm, patch_group: str, expected: int, timeout_s: float, ctx=None):
    left = ctx.time_left() if ctx is not None else None
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 5.0))
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = ssm.describe_patch_group_state(PatchGroup=patch_group)
        if state["Instances"] == expected:
            return state
        time.sleep(3.0)
    left = ctx.time_left() if ctx is not None else None
    if left is not None and left <= 6.0:
        raise TimeoutError("DescribePatchGroupState settling: the run budget ended first; not graded")
    raise AssertionError(f"DescribePatchGroupState never reported Instances={expected}: {state}")


def _wait_for_agent_online(
    ctx, instance_id: str, timeout_s: float = 600.0, interval_s: float = 15.0
) -> None:
    ssm = ctx.client("ssm")
    if ctx.time_left() is not None:
        timeout_s = max(1.0, min(timeout_s, ctx.time_left() - 60.0))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"instance {instance_id} never reached PingStatus=Online within {timeout_s:.0f}s"
        " (SSM Agent never registered)"
    )


def _launch_ssm_managed_instance(ctx, extra_tags=None) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssmrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    )

    profile_name = ctx.unique_name("sim2real-ssmprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]

    tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-node-")}]
    if extra_tags:
        tags.extend(extra_tags)

    # IAM role/instance-profile propagation lag before EC2 will accept the profile: bounded
    # retry on InvalidParameterValue rather than a fixed pre-sleep.
    instance_id = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue":
                time.sleep(5.0)
                continue
            raise
    if instance_id is None:
        raise AssertionError("could not launch an EC2 instance for the SSM managed node")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _wait_for_agent_online(ctx, instance_id)
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

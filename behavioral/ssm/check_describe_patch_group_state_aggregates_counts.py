"""describe-patch-group-state-aggregates-counts."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-patch-group-state-aggregates-counts"
GROUP = "state-machine"
SERVICES = ["ssm"]

_TRUST_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
}"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribePatchGroupState aggregates match the InstancePatchState Installed/Missing/Failed
    counts of a single patch-scanned managed node tagged into the patch group."""
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    patch_group = ctx.unique_name("sim2real-behav-patchgrp-")
    role_name = ctx.unique_name("sim2real-behav-ssmrole-")
    profile_name = ctx.unique_name("sim2real-behav-ssmprof-")
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    )

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]

    instance_id = _launch_instance_with_retry(ctx, ec2, ami_id, profile_name, patch_group)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"],
        lambda infos: len(infos) == 1 and infos[0]["PingStatus"] == "Online",
        timeout_s=480,
        interval_s=15,
        desc="managed node registration",
    )

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPatchBaseline",
        Parameters={"Operation": ["Scan"]},
    )["Command"]["CommandId"]

    def _get_invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvocationDoesNotExist":
                return {"Status": "Pending"}
            raise

    invocation = _poll_until(
        _get_invocation,
        lambda inv: inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"),
        timeout_s=480,
        interval_s=15,
        desc="AWS-RunPatchBaseline scan completion",
    )
    assert invocation["Status"] == "Success", invocation

    group_state = _poll_until(
        lambda: ssm.describe_patch_group_state(PatchGroup=patch_group),
        lambda state: state["Instances"] >= 1,
        timeout_s=180,
        interval_s=10,
        desc="patch group membership propagation",
    )
    assert group_state["Instances"] == 1, group_state

    instance_states = ssm.describe_instance_patch_states_for_patch_group(PatchGroup=patch_group)[
        "InstancePatchStates"
    ]
    assert len(instance_states) == 1, instance_states
    instance_state = instance_states[0]
    assert instance_state["InstanceId"] == instance_id, (
        f"expected InstancePatchState for {instance_id}, got {instance_state['InstanceId']}"
    )

    # The group-level aggregate must be consistent with the single member's state:
    # a nonzero per-instance count implies exactly one instance counted at the group level.
    if instance_state["InstalledCount"] > 0:
        assert group_state["InstancesWithInstalledPatches"] == 1, group_state
    else:
        assert group_state["InstancesWithInstalledPatches"] == 0, group_state
    if instance_state["MissingCount"] > 0:
        assert group_state["InstancesWithMissingPatches"] == 1, group_state
    else:
        assert group_state["InstancesWithMissingPatches"] == 0, group_state
    if instance_state["FailedCount"] > 0:
        assert group_state["InstancesWithFailedPatches"] == 1, group_state
    else:
        assert group_state["InstancesWithFailedPatches"] == 0, group_state


def _launch_instance_with_retry(ctx, ec2, ami_id, profile_name, patch_group):
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-patchhost-")},
                            {"Key": "Patch Group", "Value": patch_group},
                        ],
                    }
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            return resp["Instances"][0]["InstanceId"]
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] == "InvalidParameterValue" and "profile" in str(err).lower():
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not launch instance with instance profile in time: {last_err}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last observed value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

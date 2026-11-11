"""op-contract-associate-iam-instance-profile-duplicate-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-associate-iam-instance-profile-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateIamInstanceProfile binds a profile to an instance; a second profile on the same
    instance fails IncorrectState with its exact message and leaves one association, and the call
    succeeds after the first profile is disassociated.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    instance_id, _subnet_id, _vpc_id = _launch_instance(ctx)

    profile_name1, arn1 = _create_instance_profile(ctx, iam)
    profile_name2, arn2 = _create_instance_profile(ctx, iam)

    current_assoc_id: dict[str, str | None] = {"id": None}

    def _cleanup_current_assoc():
        aid = current_assoc_id["id"]
        if aid is None:
            return
        try:
            ec2.disassociate_iam_instance_profile(AssociationId=aid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAssociationID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_current_assoc)

    assoc = _wait_association_created(ec2, instance_id, profile_name1)
    assoc_id = assoc["AssociationId"]
    current_assoc_id["id"] = assoc_id
    assert assoc["IamInstanceProfile"]["Arn"] == arn1, (
        f"expected profile arn {arn1}, got {assoc['IamInstanceProfile']['Arn']}"
    )
    assert assoc["InstanceId"] == instance_id, (
        f"expected association on instance {instance_id}, got {assoc['InstanceId']}"
    )

    described = ec2.describe_iam_instance_profile_associations(AssociationIds=[assoc_id])[
        "IamInstanceProfileAssociations"
    ][0]
    assert described["State"] in ("associating", "associated"), (
        f"unexpected initial association state: {described['State']!r}"
    )

    _poll_until(
        lambda: ec2.describe_iam_instance_profile_associations(AssociationIds=[assoc_id])[
            "IamInstanceProfileAssociations"
        ][0]["State"],
        lambda state: state == "associated",
        timeout_s=60,
        interval_s=3,
    )

    # break: a second association is rejected while the first is live (state conflict)
    code, message = _client_error(
        lambda: ec2.associate_iam_instance_profile(
            IamInstanceProfile={"Name": profile_name2}, InstanceId=instance_id
        )
    )
    assert code == "IncorrectState", f"unexpected error code for duplicate association: {code!r}"
    expected = f"There is an existing association for instance {instance_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect-absent: the rejection created nothing; the instance still holds exactly the first association
    active = _active_associations(ec2, instance_id)
    assert len(active) == 1 and active[0]["AssociationId"] == assoc_id, (
        f"expected only {assoc_id} live after the rejected duplicate, "
        f"got {[a['AssociationId'] for a in active]}"
    )
    assert active[0]["IamInstanceProfile"]["Arn"] == arn1, (
        f"expected {arn1} still associated after the rejected duplicate, "
        f"got {active[0]['IamInstanceProfile']['Arn']}"
    )

    # restore: lift the state conflict by disassociating the first profile
    ec2.disassociate_iam_instance_profile(AssociationId=assoc_id)
    current_assoc_id["id"] = None
    _poll_until(
        lambda: _active_associations(ec2, instance_id),
        lambda active: active == [],
        timeout_s=120,
        interval_s=3,
    )

    # the identical call now succeeds once the conflict is gone
    restored = _wait_association_created(ec2, instance_id, profile_name2)
    restored_id = restored["AssociationId"]
    current_assoc_id["id"] = restored_id
    assert restored_id != assoc_id, f"expected a fresh association id, reused {assoc_id}"
    assert restored["IamInstanceProfile"]["Arn"] == arn2, (
        f"expected profile arn {arn2} after restore, got {restored['IamInstanceProfile']['Arn']}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _active_associations(ec2, instance_id):
    return [
        a
        for a in ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]
        )["IamInstanceProfileAssociations"]
        if a["State"] != "disassociated"
    ]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _wait_association_created(ec2, instance_id, profile_name, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return ec2.associate_iam_instance_profile(
                IamInstanceProfile={"Name": profile_name}, InstanceId=instance_id
            )["IamInstanceProfileAssociation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            time.sleep(3)
    raise AssertionError("instance profile never became associable (IAM propagation delay)")


def _create_instance_profile(ctx, iam):
    name = ctx.unique_name("sim2real-profile-")
    role_name = ctx.unique_name("sim2real-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    arn = iam.create_instance_profile(InstanceProfileName=name)["InstanceProfile"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=role_name))
    return name, arn


def _default_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, subnets[0]["SubnetId"]


def _latest_al2023_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_instance(ctx):
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-instance-")}]}
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id, subnet_id, vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

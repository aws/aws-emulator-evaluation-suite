"""cancel-update-non-cancelable-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-update-non-cancelable-state-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


_NOT_CANCELLABLE = (
    "InvalidParameterException",
    "Update is not in a cancellable state. Supported update types: VersionRollback",
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelUpdate on a non-rollback UpdateClusterConfig logging update, completed or in
    progress, is rejected with InvalidParameterException and leaves the update's status unchanged;
    only VersionRollback updates on Auto Mode clusters are cancelable."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_subnets(ctx)
    cluster_name, _cluster = _create_active_cluster(ctx, role_arn, subnet_ids)

    # Drive a small, real cluster config update to completion.
    completed_update_id = eks.update_cluster_config(
        name=cluster_name, logging={"clusterLogging": [{"types": ["api"], "enabled": True}]}
    )["update"]["id"]

    def _describe(update_id):
        return eks.describe_update(name=cluster_name, updateId=update_id)["update"]

    completed = _poll_until(
        lambda: _describe(completed_update_id), lambda u: u["status"] in ("Successful", "Failed", "Cancelled"), timeout_s=900, interval_s=15
    )
    assert completed["status"] == "Successful", f"expected the first update to complete Successfully, got {completed}"

    code = _expect_error(lambda: eks.cancel_update(name=cluster_name, updateId=completed_update_id))
    assert code == _NOT_CANCELLABLE, f"expected InvalidParameterException, got {code}"

    # effect absent: status/cancellation record is unchanged by the rejected call
    unchanged = _describe(completed_update_id)
    assert unchanged["status"] == "Successful", f"rejected cancel must not alter update status, got {unchanged}"
    assert "cancellation" not in unchanged, f"rejected cancel must not add a cancellation record, got {unchanged}"

    # Same rejection applies to a non-rollback update that is still InProgress: the
    # boundary is the update's *type* (only VersionRollback is cancelable), not merely
    # its terminal-vs-in-progress state, so a freshly-started logging update on the same
    # cluster is rejected the same way while it is still running.
    inprogress_update_id = eks.update_cluster_config(
        name=cluster_name, logging={"clusterLogging": [{"types": ["audit"], "enabled": True}]}
    )["update"]["id"]
    code2 = _expect_error(lambda: eks.cancel_update(name=cluster_name, updateId=inprogress_update_id))
    assert code2 == _NOT_CANCELLABLE, f"expected InvalidParameterException, got {code2}"

    still_running = _poll_until(
        lambda: _describe(inprogress_update_id), lambda u: u["status"] in ("Successful", "Failed", "Cancelled"), timeout_s=900, interval_s=15
    )
    assert still_running["status"] == "Successful", f"expected the second update to run to completion unaffected, got {still_running}"


_EKS_CLUSTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _expect_error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_EKS_CLUSTER_TRUST))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _retry_delete(fn, release_s: float = 540.0) -> None:
    """A deleted cluster's ENIs stay in its subnets for minutes, so DependencyViolation is retried
    every 2 s up to release_s; already gone is fine and every other error raises."""
    deadline = time.monotonic() + release_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_subnets(ctx) -> list[str]:
    """Provision a dedicated VPC+subnets rather than depending on an ambient default
    VPC, which a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    az_names = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    ][:2]
    assert len(az_names) >= 2, f"region needs at least two availability zones, found {az_names}"

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _poll_until(probe, predicate, timeout_s, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_active_cluster(ctx, role_arn: str, subnet_ids: list[str]):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-cl-")
    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 60 s,
    # capped by the run's remaining time.
    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: eks.delete_cluster(name=name))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name, cluster


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

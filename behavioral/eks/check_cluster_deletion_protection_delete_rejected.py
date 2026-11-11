"""cluster-deletion-protection-delete-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-deletion-protection-delete-rejected"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on an ACTIVE cluster with deletionProtection=True is rejected with
    InvalidRequestException and leaves the cluster intact; after UpdateClusterConfig disables
    the protection, DeleteCluster on the same cluster succeeds."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    subnet_ids = _create_vpc_and_subnets(ctx, ec2)
    cluster_role_arn = _create_cluster_role(ctx, iam)

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    _create_cluster_with_retry(
        eks,
        name=cluster_name,
        roleArn=cluster_role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        deletionProtection=True,
    )
    # cleanup net: force-disable protection (best effort) then delete, in case
    # the test body itself fails partway through
    ctx.on_cleanup(lambda: _force_delete_cluster(eks, cluster_name))

    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    described = eks.describe_cluster(name=cluster_name)["cluster"]
    assert described["status"] == "ACTIVE"
    assert described["deletionProtection"] is True

    # --- break exactly one thing: try to delete a deletion-protected cluster ---
    code, message = _error(lambda: eks.delete_cluster(name=cluster_name))
    assert code == "InvalidRequestException", f"unexpected code: {code}"
    expected = f"Cluster {cluster_name} cannot be deleted while DeletionProtection is enabled."
    assert message == expected, f"unexpected message: {message!r}, expected {expected!r}"

    # effect absent: the cluster is still there, untouched, still ACTIVE
    still_there = eks.describe_cluster(name=cluster_name)["cluster"]
    assert still_there["status"] == "ACTIVE"
    assert still_there["name"] == cluster_name

    # --- positive control: disable protection on the SAME cluster, then delete succeeds ---
    update_id = eks.update_cluster_config(name=cluster_name, deletionProtection=False)["update"][
        "id"
    ]
    final_update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=300,
        interval_s=10,
    )
    assert final_update["status"] == "Successful"

    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )
    assert eks.describe_cluster(name=cluster_name)["cluster"]["deletionProtection"] is False

    eks.delete_cluster(name=cluster_name)  # must succeed now
    _poll_until(
        lambda: _cluster_exists(eks, cluster_name),
        lambda exists: exists is False,
        timeout_s=600,
        interval_s=15,
    )

    # deletes prove gone and unusable: a mutation on the now-dead id also fails
    dead_code, dead_message = _error(
        lambda: eks.update_cluster_config(name=cluster_name, deletionProtection=True)
    )
    assert dead_code == "ResourceNotFoundException", f"unexpected code on deleted cluster: {dead_code}"
    expected = f"No cluster found for name: {cluster_name}."
    assert dead_message == expected, f"unexpected message on deleted cluster: {dead_message!r}"


# ===== helpers =====


def _error(fn) -> tuple[str, str | None]:
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_cluster_with_retry(eks, *, timeout_s: float = 90, interval_s: float = 10, **kwargs) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("ClientException", "InvalidParameterException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _cluster_exists(eks, cluster_name: str) -> bool:
    from botocore.exceptions import ClientError

    try:
        eks.describe_cluster(name=cluster_name)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise


def _poll_until(probe, predicate, timeout_s: float, interval_s: float = 15.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _safe(fn, not_found: tuple[str, ...], timeout_s: float = 120.0) -> None:
    """Run a teardown call: not_found codes count as deleted, DependencyViolation and
    ResourceInUseException are retried every 2 s while a dependency is released, the rest raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in not_found:
                return
            if code not in ("DependencyViolation", "ResourceInUseException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
    }


def _force_delete_cluster(eks, cluster_name: str) -> None:
    if not _cluster_exists(eks, cluster_name):
        return
    try:
        eks.update_cluster_config(name=cluster_name, deletionProtection=False)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            c = eks.describe_cluster(name=cluster_name)["cluster"]
            if c["status"] == "ACTIVE" and c.get("deletionProtection") is False:
                break
            time.sleep(2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _safe(lambda: eks.delete_cluster(name=cluster_name), ("ResourceNotFoundException",))
    _poll_until(lambda: _cluster_exists(eks, cluster_name), lambda exists: exists is False, timeout_s=900, interval_s=2)


def _delete_role(iam, role_name: str, policy_arns: list[str]) -> None:
    for arn in policy_arns:
        _safe(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a), ("NoSuchEntity",))
    _safe(lambda: iam.delete_role(RoleName=role_name), ("NoSuchEntity",))


def _create_cluster_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-eks-clrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, [policy_arn]))
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda pols: any(p["PolicyArn"] == policy_arn for p in pols),
        timeout_s=30,
        interval_s=3,
    )
    return role_arn


def _create_vpc_and_subnets(ctx, ec2) -> list[str]:
    vpc_id = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have at least 2 available AZs for EKS subnets")

    subnet_ids: list[str] = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.80.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: ec2.delete_subnet(SubnetId=sid), ("InvalidSubnetID.NotFound",)))

    return subnet_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

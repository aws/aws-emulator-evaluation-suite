"""cancel-update-on-version-update-rejected-update-completes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-update-on-version-update-rejected-update-completes"
GROUP = "ordering"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelUpdate on a plain UpdateClusterVersion update is rejected with
    InvalidParameterException (only Auto Mode VersionRollback updates are cancelable); the update
    is never Cancelled and completes Successful."""
    eks = ctx.client("eks")
    lower_version, higher_version = _pick_upgrade_versions(ctx)
    cluster = _create_active_cluster(ctx, version=lower_version)

    update_resp = eks.update_cluster_version(name=cluster, version=higher_version)
    update_id = update_resp["update"]["id"]

    code, message = _error(lambda: eks.cancel_update(name=cluster, updateId=update_id))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "Update is not in a cancellable state. Supported update types: VersionRollback"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The update may already have finished on a fast backend; either way it is not Cancelled.
    immediate = eks.describe_update(name=cluster, updateId=update_id)["update"]
    assert immediate["status"] in ("InProgress", "Successful"), (
        f"rejected CancelUpdate should have had no effect, but status is {immediate['status']!r}"
    )

    deadline = time.monotonic() + _budget_s(ctx, 2400)
    final_status = None
    while True:
        status = eks.describe_update(name=cluster, updateId=update_id)["update"]["status"]
        assert status != "Cancelled", (
            "update reached Cancelled even though the CancelUpdate call was rejected"
        )
        if status in ("Successful", "Failed"):
            final_status = status
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(2)

    if final_status is None and _budget_spent(ctx):
        raise TimeoutError(f"update {update_id} reaching a terminal state: the run budget ended first; not graded")
    assert final_status is not None, "update did not reach a terminal state within the timeout"
    assert final_status == "Successful", f"expected the version update to succeed, got {final_status}"

    final_cluster = eks.describe_cluster(name=cluster)["cluster"]
    assert final_cluster["version"] == higher_version




def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _pick_upgrade_versions(ctx):
    eks = ctx.client("eks")
    versions = eks.describe_cluster_versions()["clusterVersions"]
    standard = sorted(
        {v["clusterVersion"] for v in versions if v.get("status") == "STANDARD_SUPPORT"},
        key=lambda s: tuple(int(p) for p in s.split(".")),
    )
    if len(standard) < 2:
        raise AssertionError(
            "fewer than two STANDARD_SUPPORT EKS cluster versions are currently "
            "available in this account/region to exercise a version upgrade"
        )
    return standard[0], standard[1]


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _pick_subnets(ctx):
    ec2 = ctx.client("ec2")

    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:3]

    # No usable shared network (a freshly provisioned account may not have one) -- provision
    # our own rather than assuming ambient infrastructure.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.43.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    az_names = [az["ZoneName"] for az in azs][:2]
    if len(az_names) < 2:
        raise AssertionError("region needs at least two availability zones to provision an EKS cluster")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.43.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _retry_delete(fn, release_s: float = 180.0) -> None:
    """Teardown delete: already gone is fine, DependencyViolation (cluster ENIs still being
    released) is retried every 2 s up to release_s, and every other error raises."""
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


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_active_cluster(ctx, version=None):
    eks = ctx.client("eks")
    subnet_ids = _pick_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-ekscl-")
    kwargs = {"name": cluster_name, "roleArn": role_arn, "resourcesVpcConfig": {"subnetIds": subnet_ids}}
    if version:
        kwargs["version"] = version

    last_err = None
    retry_deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() >= retry_deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("create_cluster once the cluster role propagates: the run "
                                       "budget ended first; not graded") from exc
                raise AssertionError(
                    f"create_cluster never succeeded after IAM propagation retries: {last_err}") from exc
            time.sleep(2)

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))
    deadline = time.monotonic() + _budget_s(ctx, 1200)
    while True:
        status = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
        if status == "ACTIVE":
            return cluster_name
        assert status in ("CREATING", "PENDING"), f"cluster {cluster_name} entered {status} while creating"
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"cluster {cluster_name} ACTIVE: the run budget ended first; not graded")
        assert time.monotonic() < deadline, f"cluster {cluster_name} did not become ACTIVE (still {status})"
        time.sleep(2)



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network;
    ResourceInUseException (an update, node group or add-on still running) is retried."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

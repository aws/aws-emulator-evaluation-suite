"""ekscc-create-cluster-with-nonexistent-security-group-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ekscc-create-cluster-with-nonexistent-security-group-rejected"
GROUP = "negative-boundary"
SERVICES = ["ec2", "eks", "iam"]


@tags("axis:rejection", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster naming a well-formed but nonexistent additional security group id is
    refused with EKS's own not-exist message rather than a subnet's relayed EC2 text, and leaves
    no cluster; the identical call with no extra security group is accepted."""
    eks = ctx.client("eks")
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids = _own_network(ctx, ec2)
    role_arn = _cluster_role(ctx)

    unknown_sg = "sg-0" + ctx.unique_name("")[:7].ljust(7, "0")
    assert ec2.describe_security_groups(
        Filters=[{"Name": "group-id", "Values": [unknown_sg]}])["SecurityGroups"] == [], (
        f"{unknown_sg} must not exist for this probe")

    bad = ctx.unique_name("sim2real-ekscc-sg-")
    code, message = _error(lambda: _cluster(
        ctx, eks, bad, role_arn, subnet_ids, security_group_ids=[unknown_sg]))
    want = ("InvalidParameterException", f"The security group '{unknown_sg}' does not exist")
    assert (code, message) == want, (
        f"an unknown security group must be refused with {want!r}; got {(code, message)!r}")
    gone = _absent(lambda: eks.describe_cluster(name=bad))
    want_gone = ("ResourceNotFoundException", f"No cluster found for name: {bad}.")
    assert gone == want_gone, f"the refused create left a cluster: {gone!r}, expected {want_gone!r}"

    # Positive control: the identical call naming no extra security group is accepted.
    good = ctx.unique_name("sim2real-ekscc-sg-")
    created = _cluster(ctx, eks, good, role_arn, subnet_ids)
    assert created["status"] == "CREATING", f"the control should start CREATING; got {created!r}"
    assert created["resourcesVpcConfig"]["vpcId"] == vpc_id, (
        f"the control must land in {vpc_id!r}; got {created['resourcesVpcConfig']!r}")


# ===== helpers =====
_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_K8S_VERSION = "1.33"
#: A cluster deleted while CREATING is gone in seconds; an ACTIVE one takes minutes.
_GONE_DEADLINE_S = 900


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) fn() raises. RAISES when the call succeeds: real AWS rejects it."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call SUCCEEDED; real AWS rejects it, so there is no error code")


def _absent(fn) -> tuple[str, str]:
    """The (code, message) fn() raises, or ("<succeeded>", "") when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    return "<succeeded>", ""


def _absent_code(fn) -> str:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "<succeeded>"


def _cluster_role(ctx) -> str:
    """A cluster service role trusting eks.amazonaws.com with the cluster policy attached."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ekscc-sg-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _quiet(lambda: iam.delete_role(RoleName=name)))
    iam.attach_role_policy(RoleName=name, PolicyArn=_CLUSTER_POLICY)
    ctx.on_cleanup(lambda: _quiet(lambda: iam.detach_role_policy(RoleName=name,
                                                                 PolicyArn=_CLUSTER_POLICY)))
    return arn


def _own_network(ctx, ec2) -> tuple[str, list[str]]:
    """A fresh VPC with two subnets in distinct AZs, torn down after the cluster releases its ENIs."""
    tags = [{"Key": "sim2real", "Value": CHECK}]
    vpc_id = ec2.create_vpc(CidrBlock="10.95.0.0/16",
                            TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zones = sorted(z["ZoneId"] for z in ec2.describe_availability_zones(Filters=[
        {"Name": "state", "Values": ["available"]},
        {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"the region needs >= 2 available AZs; got {zones!r}"
    subnets = []
    for i, zone_id in enumerate(zones[:2]):
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.95.{i * 16}.0/20",
                                AvailabilityZoneId=zone_id,
                                TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}])[
            "Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=sid: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=s)))
        subnets.append(sid)
    return vpc_id, subnets


def _retry_dependency(fn, timeout_s: float = 600.0) -> None:
    """Teardown: retry only while an EKS-owned ENI or security group still blocks the delete."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if "NotFound" in code:
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(10)


def _cluster(ctx, eks, name: str, role_arn: str, subnet_ids: list[str],
            security_group_ids: list[str] | None = None) -> dict:
    """create_cluster with the teardown registered BEFORE the create; returns the created cluster."""
    ctx.on_cleanup(lambda: _drop_cluster_net(eks, name))
    vpc_config: dict = {"subnetIds": subnet_ids}
    if security_group_ids is not None:
        vpc_config["securityGroupIds"] = security_group_ids
    return eks.create_cluster(name=name, version=_K8S_VERSION, roleArn=role_arn,
                              resourcesVpcConfig=vpc_config)["cluster"]


def _drop_cluster(eks, name: str) -> bool:
    """Delete the cluster and wait until it no longer describes; True when it is gone."""
    deadline = time.monotonic() + _GONE_DEADLINE_S
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return True
            if code == "InvalidParameterException":
                return True  # the name never passed validation, so there is no cluster
            if code != "ResourceInUseException" or time.monotonic() > deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        if _absent_code(lambda: eks.describe_cluster(name=name)) == "ResourceNotFoundException":
            return True
        time.sleep(2)
    return False


def _drop_cluster_net(eks, name: str) -> None:
    if not _drop_cluster(eks, name):
        raise RuntimeError(f"eks cluster {name} still describes {_GONE_DEADLINE_S}s after delete")


def _quiet(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if "NotFound" not in code and code != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

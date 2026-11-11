"""server-side-access-entry-policy-enforcement."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-access-entry-policy-enforcement"
GROUP = "server-side"
SERVICES = ["eks"]

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy attached with AssociateAccessPolicy appears in ListAssociatedAccessPolicies at once
    (repeat calls agree), and DisassociateAccessPolicy removes it from that list just as promptly.
    """
    eks = ctx.client("eks")
    cluster = _create_active_eks_cluster(ctx)
    principal_arn = _create_throwaway_principal(ctx)

    _create_access_entry_with_retry(eks, cluster, principal_arn)

    view_policy_arn = _find_access_policy_arn(eks, "AmazonEKSViewPolicy")

    eks.associate_access_policy(
        clusterName=cluster,
        principalArn=principal_arn,
        policyArn=view_policy_arn,
        accessScope={"type": "cluster"},
    )

    for _ in range(2):
        associated = eks.list_associated_access_policies(clusterName=cluster, principalArn=principal_arn)[
            "associatedAccessPolicies"
        ]
        assert len(associated) == 1, f"expected exactly 1 associated policy, got {associated}"
        assert associated[0]["policyArn"] == view_policy_arn, (
            f"expected policyArn {view_policy_arn}, got {associated[0]['policyArn']}"
        )
        assert associated[0]["accessScope"]["type"] == "cluster", (
            f"expected accessScope type 'cluster', got {associated[0]['accessScope']['type']}"
        )

    eks.disassociate_access_policy(clusterName=cluster, principalArn=principal_arn, policyArn=view_policy_arn)

    after = eks.list_associated_access_policies(clusterName=cluster, principalArn=principal_arn)[
        "associatedAccessPolicies"
    ]
    assert after == [], f"expected no associated policies after disassociation, got {after}"


def _find_access_policy_arn(eks, policy_name):
    next_token = None
    while True:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = eks.list_access_policies(**kwargs)
        for policy in resp["accessPolicies"]:
            if policy["name"] == policy_name:
                return policy["arn"]
        next_token = resp.get("nextToken")
        if not next_token:
            raise AssertionError(f"access policy {policy_name} not found in ListAccessPolicies")


def _create_throwaway_principal(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-access-principal-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _ec2_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real-managed", "Value": "true"}]


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_eks_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.84.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags(ctx.unique_name("sim2real-eks-vpc-"))}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.84.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags(ctx.unique_name(f"sim2real-eks-sn{i}-"))}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
    return subnet_ids


def _wait_cluster_status(eks, name, target, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == target:
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {target}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s")


def _wait_cluster_gone(eks, name, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not removed within {timeout_s}s")


def _create_access_entry_with_retry(eks, cluster, principal_arn):
    deadline = time.monotonic() + 60
    while True:
        try:
            eks.create_access_entry(clusterName=cluster, principalArn=principal_arn, type="STANDARD")
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterException" and "principal" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_cluster_with_retry(eks, **kwargs):
    deadline = time.monotonic() + 90
    while True:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _create_active_eks_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_eks_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-clu-")
    _create_cluster_with_retry(
        eks,
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
    )

    def _cleanup():
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _wait_cluster_gone(eks, name)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(eks, name, "ACTIVE")
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

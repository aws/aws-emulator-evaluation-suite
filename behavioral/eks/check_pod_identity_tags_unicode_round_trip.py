"""pod-identity-tags-unicode-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pod-identity-tags-unicode-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode/emoji tag values written via TagResource on a PodIdentityAssociation come
    back byte-identical from both ListTagsForResource and DescribePodIdentityAssociation."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    pod_role_arn = _create_pod_identity_role(ctx)
    namespace = "default"
    service_account = ctx.unique_name("podsvc-").lower().replace("_", "-")

    resp = eks.create_pod_identity_association(
        clusterName=cluster["name"],
        namespace=namespace,
        serviceAccount=service_account,
        roleArn=pod_role_arn,
    )
    association = resp["association"]
    association_arn = association["associationArn"]
    association_id = association["associationId"]
    ctx.on_cleanup(
        lambda: eks.delete_pod_identity_association(
            clusterName=cluster["name"], associationId=association_id
        )
    )

    unicode_value = "héllo.世界.tëst.Ω.日本語"
    eks.tag_resource(resourceArn=association_arn, tags={"sim2real-emoji": unicode_value})

    tags_from_list = eks.list_tags_for_resource(resourceArn=association_arn)["tags"]
    assert tags_from_list["sim2real-emoji"] == unicode_value, (
        f"ListTagsForResource mangled the Unicode tag value: "
        f"expected {unicode_value!r}, got {tags_from_list.get('sim2real-emoji')!r}"
    )

    described = eks.describe_pod_identity_association(
        clusterName=cluster["name"], associationId=association_id
    )["association"]
    assert described["tags"]["sim2real-emoji"] == unicode_value, (
        f"DescribePodIdentityAssociation mangled the Unicode tag value: "
        f"expected {unicode_value!r}, got {described['tags'].get('sim2real-emoji')!r}"
    )

    # A second read must return the exact same bytes, not a re-encoded/mangled copy.
    described_again = eks.describe_pod_identity_association(
        clusterName=cluster["name"], associationId=association_id
    )["association"]
    assert described_again["tags"]["sim2real-emoji"] == unicode_value, (
        f"DescribePodIdentityAssociation changed the Unicode tag value on a repeated read: "
        f"expected {unicode_value!r}, got {described_again['tags'].get('sim2real-emoji')!r}"
    )
    assert described_again["tags"]["sim2real-emoji"] == described["tags"]["sim2real-emoji"], (
        f"two independent reads of the same association returned different tag bytes: "
        f"{described['tags']['sim2real-emoji']!r} vs {described_again['tags']['sim2real-emoji']!r}"
    )


def _get_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in at least two availability zones required by EKS")
    return list(by_az.values())[:2]


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
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
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


def _create_pod_identity_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podid-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _poll_until(probe, predicate, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=15.0):
    eks = ctx.client("eks")
    return _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnets = _get_two_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})

    def _cleanup():
        try:
            _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup)
    desc = _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
    if desc["status"] != "ACTIVE":
        raise AssertionError(f"cluster {name} entered status {desc['status']} instead of ACTIVE")
    return {"name": name, "arn": desc["arn"], "role_arn": role_arn, "subnets": subnets}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

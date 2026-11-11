"""pod-identity-association-update-changes-role-binding."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pod-identity-association-update-changes-role-binding"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePodIdentityAssociation swaps the bound IAM role: DescribePodIdentityAssociation
    reflects the new roleArn and the previously bound role is no longer associated.

    See https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdatePodIdentityAssociation.html
    """
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    cluster = _ensure_active_cluster(ctx)
    name = cluster["name"]

    role_a_arn = _create_pod_identity_role(ctx)
    role_b_arn = _create_pod_identity_role(ctx)

    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-").lower().replace("_", "-")

    create_resp = eks.create_pod_identity_association(
        clusterName=name, namespace=namespace, serviceAccount=service_account, roleArn=role_a_arn
    )
    association = create_resp["association"]
    assoc_id = association["associationId"]

    def _cleanup_association() -> None:
        try:
            eks.delete_pod_identity_association(clusterName=name, associationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_association)
    assert association["roleArn"] == role_a_arn, (
        f"CreatePodIdentityAssociation returned roleArn={association['roleArn']!r}, expected {role_a_arn!r}"
    )

    update_resp = eks.update_pod_identity_association(
        clusterName=name, associationId=assoc_id, roleArn=role_b_arn
    )
    assert update_resp["association"]["roleArn"] == role_b_arn, (
        f"UpdatePodIdentityAssociation response roleArn={update_resp['association']['roleArn']!r}, "
        f"expected {role_b_arn!r}"
    )
    assert update_resp["association"]["roleArn"] != role_a_arn, (
        f"UpdatePodIdentityAssociation response still shows the prior role {role_a_arn!r} after the update"
    )

    described = eks.describe_pod_identity_association(clusterName=name, associationId=assoc_id)["association"]
    assert described["roleArn"] == role_b_arn, "DescribePodIdentityAssociation did not reflect the updated role"
    assert described["roleArn"] != role_a_arn, "the prior role is still bound after the update"
    assert described["namespace"] == namespace, (
        f"namespace changed by the role update: got {described['namespace']!r}, expected {namespace!r}"
    )
    assert described["serviceAccount"] == service_account, (
        f"serviceAccount changed by the role update: got {described['serviceAccount']!r}, "
        f"expected {service_account!r}"
    )

    eks.delete_pod_identity_association(clusterName=name, associationId=assoc_id)
    not_found = f"No service account role association found for ID: {assoc_id}"
    try:
        eks.describe_pod_identity_association(clusterName=name, associationId=assoc_id)
        raise AssertionError(
            "DescribePodIdentityAssociation succeeded after delete; expected ResourceNotFoundException"
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"describe after delete raised {exc.response['Error']['Code']!r}, expected ResourceNotFoundException"
        )
        assert exc.response["Error"]["Message"] == not_found, exc.response["Error"]["Message"]
    try:
        eks.update_pod_identity_association(clusterName=name, associationId=assoc_id, roleArn=role_a_arn)
        raise AssertionError(
            "UpdatePodIdentityAssociation succeeded against a deleted association; "
            "expected ResourceNotFoundException"
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"update against deleted association raised {exc.response['Error']['Code']!r}, "
            f"expected ResourceNotFoundException"
        )
        assert exc.response["Error"]["Message"] == not_found, exc.response["Error"]["Message"]


# ===== helpers =====

def _create_pod_identity_role(ctx) -> str:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podid-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "pods.eks.amazonaws.com"},
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                }
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _ensure_active_cluster(ctx) -> dict[str, str]:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    eks = ctx.client("eks")

    role_name = ctx.unique_name("sim2real-eks-role-")
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

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host a test EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:3]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network lacks subnets in >=2 AZs required to create an EKS cluster")

    cluster_name = ctx.unique_name("sim2real-eks-")
    # A new role is rejected as InvalidParameterException until IAM propagates it.
    create_deadline = time.monotonic() + 80
    left = ctx.time_left()
    if left is not None:
        create_deadline = min(create_deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= create_deadline:
                raise
            time.sleep(2)

    def _cleanup_cluster():
        try:
            eks.delete_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        deadline = time.monotonic() + 15 * 60
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=cluster_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(15)

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + 25 * 60
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=cluster_name)["cluster"]
        if desc["status"] == "ACTIVE":
            return {"name": cluster_name, "arn": desc["arn"], "role_arn": role_arn, "version": desc["version"]}
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {cluster_name} entered FAILED state while creating: {desc}")
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_name} did not become ACTIVE within timeout: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

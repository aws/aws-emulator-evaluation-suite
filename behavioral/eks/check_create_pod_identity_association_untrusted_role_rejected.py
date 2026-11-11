"""create-pod-identity-association-untrusted-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pod-identity-association-untrusted-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePodIdentityAssociation with a role that trusts ec2.amazonaws.com fails with
    InvalidParameterException and creates nothing, while a role trusting pods.eks.amazonaws.com creates an
    association that describes, then deletes and fails Describe with ResourceNotFoundException.
    """
    eks = ctx.client("eks")
    subnet_ids = _pick_two_az_subnets(ctx)
    cluster_role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])

    cluster_name = ctx.unique_name("sim2real-eks-pia-")
    _create_cluster_with_retry(eks, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1500)

    untrusted_role_arn = _create_role_with_trust(
        ctx,
        "sim2real-eks-untrusted-",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        },
    )
    trusted_role_arn = _create_role_with_trust(
        ctx,
        "sim2real-eks-trusted-",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "pods.eks.amazonaws.com"},
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                }
            ],
        },
    )

    namespace = "default"
    bad_service_account = ctx.unique_name("sim2real-sa-bad-")
    code, message = _error(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace=namespace,
            serviceAccount=bad_service_account,
            roleArn=untrusted_role_arn,
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == (
        "Trust policy of the role provided is invalid. Follow the official documentation to resolve the issue."
    ), message

    # Effect absent: no association was created for the rejected attempt.
    listed = eks.list_pod_identity_associations(
        clusterName=cluster_name, namespace=namespace, serviceAccount=bad_service_account
    )["associations"]
    assert not listed, "an association exists despite the untrusted-role CreatePodIdentityAssociation being rejected"

    # Positive control: a role that DOES carry the required trust statement is accepted.
    good_service_account = ctx.unique_name("sim2real-sa-good-")
    created = eks.create_pod_identity_association(
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=good_service_account,
        roleArn=trusted_role_arn,
    )["association"]
    association_id = created["associationId"]
    ctx.on_cleanup(lambda: _safe_delete_association(eks, cluster_name, association_id))
    assert created["roleArn"] == trusted_role_arn, f"expected roleArn {trusted_role_arn!r}, got {created['roleArn']!r}"
    assert created["serviceAccount"] == good_service_account, (
        f"expected serviceAccount {good_service_account!r}, got {created['serviceAccount']!r}"
    )

    # Independent read: the association is visible through a different operation than
    # the one that created it, not just echoed back in the mutating response.
    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert described["associationId"] == association_id, (
        f"expected associationId {association_id!r}, got {described['associationId']!r}"
    )
    assert described["roleArn"] == trusted_role_arn, (
        f"expected roleArn {trusted_role_arn!r} on independent read, got {described['roleArn']!r}"
    )

    # Delete proves gone and unusable.
    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    not_found_code, not_found_message = _error(
        lambda: eks.describe_pod_identity_association(
            clusterName=cluster_name, associationId=association_id
        )
    )
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_message == f"No service account role association found for ID: {association_id}", (
        not_found_message
    )
    remaining_ids = {
        a["associationId"]
        for a in eks.list_pod_identity_associations(clusterName=cluster_name)["associations"]
    }
    assert association_id not in remaining_ids, (
        f"deleted association {association_id!r} still present in list: {remaining_ids!r}"
    )


def _error(fn):
    """The (code, message) fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _pick_two_az_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an EKS test cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    return list(by_az.values())[:2]


def _create_role(ctx, service_principal: str, managed_policy_names: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, managed_policy_names))
    for policy_name in managed_policy_names:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
    return role_arn


def _create_role_with_trust(ctx, prefix: str, trust_policy: dict) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, name, []))
    _poll_until(
        lambda: iam.get_role(RoleName=name)["Role"]["Arn"],
        lambda arn: arn == role_arn,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return role_arn


def _safe_delete_role(ctx, role_name: str, managed_policy_names: list[str]) -> None:
    iam = ctx.client("iam")
    for policy_name in managed_policy_names:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_cluster_with_retry(eks, name: str, role_arn: str, subnet_ids: list[str], timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real:managed": "true"},
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _wait_cluster_status(ctx, eks, name: str, want: str, timeout_s: float, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {want} within {timeout_s}s (last={last})")


def _wait_cluster_gone(ctx, eks, name: str, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _safe_delete_cluster(ctx, eks, name: str) -> None:
    _delete_eks_cluster_retrying(eks, name)
    _wait_cluster_gone(ctx, eks, name, timeout_s=900)


def _safe_delete_association(eks, cluster_name: str, association_id: str) -> None:
    try:
        eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

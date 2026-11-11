"""create-certificate-authority-invalid-parameter-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-certificate-authority-invalid-parameter-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority on a RegisterCluster-connected cluster (no EKS-hosted CA) is
    rejected with ClientException and leaves it untouched, while the identical call on an
    EKS-hosted ACTIVE cluster returns a successor CA visible via Describe and List."""
    eks = ctx.client("eks")
    connector_role_arn = _create_connector_role(ctx)
    connected_name = _register_connected_cluster(ctx, connector_role_arn)
    status_before = eks.describe_cluster(name=connected_name)["cluster"]["status"]

    code, message = _error(lambda: eks.create_certificate_authority(clusterName=connected_name))
    assert code == "ClientException", f"expected ClientException, got {code}"
    assert message == "This operation is not supported for connected clusters", (
        f"unexpected message: {message!r}"
    )

    # effect absent: the registered cluster's status is unaffected by the rejected call
    status_after = eks.describe_cluster(name=connected_name)["cluster"]["status"]
    assert status_after == status_before, (
        f"registered cluster {connected_name} status drifted from {status_before!r} to "
        f"{status_after!r} after the rejected CreateCertificateAuthority call"
    )

    # positive control: an EKS-hosted, ACTIVE cluster accepts CreateCertificateAuthority
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _get_subnets(ctx)
    hosted_name, _cluster = _create_active_cluster(ctx, role_arn, subnet_ids)
    resp = eks.create_certificate_authority(clusterName=hosted_name)
    ca_id = resp["certificateAuthority"]["id"]
    assert resp["certificateAuthority"]["signingStatus"] == "NOT_USED", (
        f"successor CA {ca_id} on hosted cluster {hosted_name} reported signingStatus "
        f"{resp['certificateAuthority']['signingStatus']!r}, expected NOT_USED"
    )
    assert resp["update"]["type"] == "CertificateAuthorityUpdate", (
        f"CreateCertificateAuthority on {hosted_name} returned update type "
        f"{resp['update']['type']!r}, expected CertificateAuthorityUpdate"
    )

    # terminal assertion is an INDEPENDENT read (DescribeCertificateAuthority), not the mutating
    # call's own response: the successor CA must actually be visible, server-side, at the
    # cluster's certificate-authority store.
    independent = eks.describe_certificate_authority(
        clusterName=hosted_name, certificateAuthorityId=ca_id
    )["certificateAuthority"]
    assert independent["signingStatus"] == "NOT_USED", (
        f"DescribeCertificateAuthority for {ca_id} on {hosted_name} reports signingStatus "
        f"{independent['signingStatus']!r}, expected NOT_USED"
    )
    listed_ids = {
        ca["id"]
        for ca in eks.list_certificate_authorities(clusterName=hosted_name)["certificateAuthorities"]
    }
    assert ca_id in listed_ids, (
        f"successor CA {ca_id} not present in ListCertificateAuthorities({hosted_name}); "
        f"observed ids: {listed_ids}"
    )


# ===== helpers =====
_EKS_CLUSTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}
_SSM_CONNECTOR_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _error(fn):
    """Call fn(); return its botocore Error (Code, Message). An unexpected SUCCESS raises, so accepting
    input AWS refuses fails as acceptance rather than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_connector_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-connector-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_SSM_CONNECTOR_TRUST),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


def _register_connected_cluster(ctx, connector_role_arn: str) -> str:
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-connected-")
    last_err = None
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            eks.register_cluster(
                name=name,
                connectorConfig={"roleArn": connector_role_arn, "provider": "EC2"},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as e:
            last_err = e
            code = e.response["Error"]["Code"]
            if code in ("ResourcePropagationDelayException", "InvalidRequestException"):
                time.sleep(2)
                continue
            raise
    else:
        raise last_err
    ctx.on_cleanup(lambda: eks.deregister_cluster(name=name))
    return name


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_EKS_CLUSTER_TRUST),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _get_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    assert len(subnet_ids) >= 2, f"need >=2 AZ-distinct subnets in vpc {vpc_id}, found {subnet_ids}"
    return subnet_ids[:3]


def _poll_until(probe, predicate, timeout_s, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _delete_cluster_when_idle(eks, name, timeout_s=1200):
    """Teardown: a successor CA leaves a cluster update in flight, and DeleteCluster refuses
    a cluster with an update in progress, so retry ResourceInUseException (bounded)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(20)


def _create_active_cluster(ctx, role_arn: str, subnet_ids: list[str]):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-cl-")
    # A brand-new IAM role is rejected with InvalidParameterException until it propagates.
    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: _delete_cluster_when_idle(eks, name))
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

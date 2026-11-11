"""create-cluster-service-ipv4-cidr-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-service-ipv4-cidr-rejected"
GROUP = 'overly-permissive'
SERVICES = ['eks']

_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
# Substrings that mark an error as IAM-propagation noise rather than the
# rejection under test, so the assertion loop can retry instead of mis-attributing.
_PROPAGATION_HINTS = ("role", "propagat", "assume")


# _ensure_role mints a unique cluster role and registers its deletion. _stable_error keeps a
# just-created role's propagation window from being mistaken for the rejection
# under test.


def _expect_error(fn):
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _stable_error(fn, *, timeout_s=300, interval_s=15):
    """Call fn until it raises an error that is NOT IAM-propagation noise.

    Returns (Code, Message). A brand-new IAM role reads as nonexistent to EKS for
    a few seconds, and that surfaces as the same InvalidParameterException the
    rejection under test uses -- so retry, bounded, while the message looks like
    propagation. 300s is generous for IAM's documented eventual consistency.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, msg = err.get("Code", ""), err.get("Message", "")
            low = msg.lower()
            if (
                any(hint in low for hint in _PROPAGATION_HINTS)
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            return code, msg
        raise AssertionError("expected CreateCluster to be refused, but it succeeded")


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole"],
                }
            ],
        }
    )


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get(
            "AttachedPolicies", []
        ):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create a throwaway IAM role, register teardown, return its ARN.

    No blind sleep for IAM propagation here: the first call that uses this role
    goes through `_stable_error`, which already retries, bounded, while the
    error looks like propagation noise rather than the rejection under test.
    """
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="candidates_09 eks fidelity check",
            Tags=[{"Key": "simparity-check", "Value": CHECK}],
        )["Role"]["Arn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"identity cannot create IAM role {name}: {exc}") from exc
        raise
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the shared network."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster fails with InvalidParameterException and its exact message for an out-of-range service
    CIDR, an out-of-range prefix and IPV6 with a service CIDR, creating no cluster; a legal CIDR passes and
    fails only on the single-AZ subnets.
    """
    c = ctx.client("eks")
    role_arn = _ensure_role(
        ctx,
        ctx.unique_name("sim2real-behav-eks-cidr-"),
        "eks.amazonaws.com",
        [_EKS_CLUSTER_POLICY],
    )
    subnets = _subnet_ids(ctx)
    name = ctx.unique_name("sim2real-behav-eks-cidr-")

    def create(**overrides):
        body = {
            "name": name,
            "roleArn": role_arn,
            "resourcesVpcConfig": {"subnetIds": subnets},
        }
        body.update(overrides)
        return lambda: c.create_cluster(**body)

    # --- Break 1: a non-private (RFC 5737) range. EKS only accepts a service CIDR inside
    #     10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16.
    code, msg = _stable_error(
        create(kubernetesNetworkConfig={"serviceIpv4Cidr": "192.0.2.0/24"})
    )
    assert code == "InvalidParameterException", (
        f"non-private serviceIpv4Cidr 192.0.2.0/24 -> {code}: {msg}"
    )
    assert msg == (
        f"Invalid Cluster Service Ipv4 CIDR 192.0.2.0/24 for the cluster {name}, "
        "must be within RFC1918 range"
    ), msg

    # --- Break 2: a legal range but a prefix outside the /24../12 window.
    code, msg = _stable_error(
        create(kubernetesNetworkConfig={"serviceIpv4Cidr": "10.100.0.0/28"})
    )
    assert code == "InvalidParameterException", (
        f"serviceIpv4Cidr 10.100.0.0/28 (prefix outside /24../12) -> {code}: {msg}"
    )
    assert msg == (
        f"Invalid Cluster Service Ipv4 CIDR 10.100.0.0/28 for the cluster {name}, "
        "must have netmask size between /12 and /24 inclusive"
    ), msg

    # --- Break 3: ipFamily IPV6 is mutually exclusive with a service IPv4 CIDR.
    code, msg = _stable_error(
        create(
            kubernetesNetworkConfig={
                "ipFamily": "IPV6",
                "serviceIpv4Cidr": "10.100.0.0/16",
            }
        )
    )
    assert code == "InvalidParameterException", (
        f"ipFamily=IPV6 together with serviceIpv4Cidr -> {code}: {msg}"
    )
    assert msg == 'serviceIpv4Cidr cannot be specified when creating an "ipv6" cluster', msg

    # --- Effect absent: none of the three refusals created anything.
    code, msg = _expect_error(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", (
        f"a refused CreateCluster still materialised {name}: {code}"
    )
    assert msg == f"No cluster found for name: {name}.", msg
    assert name not in c.list_clusters(maxResults=100).get("clusters", []), (
        f"{name} appeared in ListClusters after three refused CreateCluster calls"
    )

    # --- Control: a LEGAL service CIDR must get past CIDR validation. Proven
    #     without provisioning by simultaneously supplying a single-AZ subnet set,
    #     so the call still fails -- but on the subnets, not the CIDR.
    code, msg = _stable_error(
        lambda: c.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnets[:1]},
            kubernetesNetworkConfig={"serviceIpv4Cidr": "10.100.0.0/16"},
        )
    )
    assert code == "InvalidParameterException", (
        f"legal CIDR + single-AZ subnets -> {code}: {msg}"
    )
    assert msg == "Subnets specified must be in at least two different AZs", (
        f"a LEGAL serviceIpv4Cidr (10.100.0.0/16) must pass CIDR validation and "
        f"fail on the subnets instead: {msg!r}"
    )
    code, msg = _expect_error(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", (
        f"the control CreateCluster still materialised {name}: {code}"
    )
    assert msg == f"No cluster found for name: {name}.", msg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

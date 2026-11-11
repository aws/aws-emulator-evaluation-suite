"""create-cluster-single-az-subnet-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-single-az-subnet-rejected"
GROUP = 'overly-permissive'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
# Substrings that mark an error as IAM-propagation noise rather than the
# rejection under test, so the assertion loop can retry instead of mis-attributing.
_PROPAGATION_HINTS = ("role", "propagat", "assume")


def _error_code(fn, *, timeout_s=180, interval_s=10):
    """Call fn until it raises an error that is NOT IAM-propagation noise; return (Code, Message).

    A brand-new IAM role reads as unusable to EKS for a few seconds after creation, and
    that surfaces as the same InvalidParameterException the rejection under test uses --
    so retry, bounded, while the message looks like propagation lag rather than the
    rejection itself.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response["Error"]
            code, msg = err["Code"], err.get("Message", "")
            if any(hint in msg.lower() for hint in _PROPAGATION_HINTS) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, msg
        raise AssertionError("expected the call to fail, but it succeeded")


def _trust(service, extra_actions=()):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole", *extra_actions],
                }
            ],
        }
    )


def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
            Tags=[{"Key": "sim2real-behav", "Value": "true"}],
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the shared network."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster fails with InvalidParameterException and a message naming the cause for a single-AZ
    subnet set, version 1.15, nonexistent subnets and a name with a leading hyphen, and no cluster is
    describable or listed afterwards.
    """
    c = ctx.client("eks")
    cluster_role = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    subnets = _subnet_ids(ctx)
    name = ctx.unique_name("clu-bad-")

    # A single subnet cannot satisfy EKS's >=2-AZ requirement.
    code, msg = _error_code(
        lambda: c.create_cluster(
            name=name,
            roleArn=cluster_role,
            resourcesVpcConfig={"subnetIds": subnets[:1]},
        )
    )
    assert code == "InvalidParameterException", f"single subnet -> {code}: {msg}"
    assert msg == "Subnets specified must be in at least two different AZs", msg
    code, msg = _error_code(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {msg}"
    assert msg == f"No cluster found for name: {name}.", msg

    # An unsupported Kubernetes version must be rejected up front too -- with VALID multi-AZ subnets
    # this time.
    code, msg = _error_code(
        lambda: c.create_cluster(
            name=name,
            roleArn=cluster_role,
            version="1.15",
            resourcesVpcConfig={"subnetIds": subnets},
        )
    )
    assert code == "InvalidParameterException", f"unsupported version -> {code}: {msg}"
    assert msg == "unsupported Kubernetes version 1.15", msg

    # So must subnet ids that do not exist in this account.
    code, msg = _error_code(
        lambda: c.create_cluster(
            name=name,
            roleArn=cluster_role,
            resourcesVpcConfig={"subnetIds": ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]},
        )
    )
    assert code == "InvalidParameterException", f"nonexistent subnets -> {code}: {msg}"
    # message varies: EKS relays EC2's InvalidSubnetID.NotFound text, which embeds the
    # upstream EC2 request id, so the stable part is graded: the rejection names the subnet.
    assert "subnet" in msg.lower(), f"rejection must name the subnet, got {msg!r}"

    # A name that violates the cluster-name pattern must be refused outright.
    code, msg = _error_code(
        lambda: c.create_cluster(
            name="-sim2real-behav-bad-name",
            roleArn=cluster_role,
            resourcesVpcConfig={"subnetIds": subnets},
        )
    )
    assert code == "InvalidParameterException", f"bad name -> {code}: {msg}"
    assert msg == (
        'The parameter name contains invalid characters. It should conform to the regular '
        'expression "^[0-9A-Za-z][A-Za-z0-9-_]*"In other words, it should start with a number '
        'or letter, and can contain numbers, letters, dashes, and underscores.'
    ), msg

    code, msg = _error_code(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {msg}"
    assert msg == f"No cluster found for name: {name}.", msg
    clusters = c.list_clusters()["clusters"]
    assert name not in clusters, f"{name} appeared in ListClusters after refused CreateCluster calls"
    assert "-sim2real-behav-bad-name" not in clusters, "invalid cluster name appeared in ListClusters"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

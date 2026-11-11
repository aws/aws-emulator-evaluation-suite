"""create-capability-argocd-config-on-ack-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-capability-argocd-config-on-ack-type-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapability of type ACK with an ARGOCD-only argoCd configuration fails with
    InvalidParameterException naming the type/configuration mismatch, and creates nothing.
    The same ACK capability without that configuration is accepted."""
    eks = ctx.client("eks")
    cluster_role_arn = _create_cluster_role(ctx)
    subnet_ids = _get_subnets(ctx)
    cluster_name, _cluster = _create_active_cluster(ctx, cluster_role_arn, subnet_ids)
    capability_role_arn = _create_capability_role(ctx)

    bad_capability_name = ctx.unique_name("sim2real-cap-bad-")
    refusal: dict = {}
    code = _create_capability_with_trust_retry(
        eks,
        refusal=refusal,
        clusterName=cluster_name,
        capabilityName=bad_capability_name,
        type="ACK",
        roleArn=capability_role_arn,
        deletePropagationPolicy="RETAIN",
        configuration={
            "argoCd": {
                "namespace": "argocd",
                "awsIdc": {"idcInstanceArn": "arn:aws:sso:::instance/ssoins-0000000000000000"},
            }
        },
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert refusal.get("message") == _MISMATCH_MESSAGE, (
        f"expected the refusal to name the type/configuration mismatch, got {refusal.get('message')!r}"
    )

    names = [c["capabilityName"] for c in eks.list_capabilities(clusterName=cluster_name)["capabilities"]]
    assert bad_capability_name not in names, f"rejected create must not persist a capability: {names}"

    good_capability_name = ctx.unique_name("sim2real-cap-good-")
    code = _create_capability_with_trust_retry(
        eks,
        clusterName=cluster_name,
        capabilityName=good_capability_name,
        type="ACK",
        roleArn=capability_role_arn,
        deletePropagationPolicy="RETAIN",
    )
    assert code is None, f"expected the unmismatched ACK capability to be accepted, got {code}"
    ctx.on_cleanup(lambda: _delete_capability_and_wait(eks, cluster_name, good_capability_name))

    described = _describe_capability_tolerating_lag(eks, cluster_name, good_capability_name)
    assert described["type"] == "ACK", f"expected type ACK, got {described.get('type')}"
    assert described["status"] in ("CREATING", "ACTIVE"), f"unexpected status {described.get('status')}"


#: CreateCapability's refusal of an argoCd configuration on an ACK-typed capability.
_MISMATCH_MESSAGE = "Mismatch between capability type and configuration"

_EKS_CLUSTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_EKS_CLUSTER_TRUST))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


_EKS_CAPABILITIES_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "capabilities.eks.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }
    ],
}


def _create_capability_role(ctx) -> str:
    # A capability's role must trust capabilities.eks.amazonaws.com (not eks.amazonaws.com) for
    # sts:AssumeRole + sts:TagSession. Broad permissions keep the permission boundary out of the
    # way of the type/configuration mismatch under test.
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-cap-role-")
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_EKS_CAPABILITIES_TRUST))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_capability_with_trust_retry(eks, attempts=10, delay_s=10, refusal=None, **kwargs):
    """Return CreateCapability's error code, or None on success.

    Retries only the trust-policy InvalidParameterException a just-created IAM role can cause."""
    last_code, last_message = None, ""
    for _ in range(attempts):
        try:
            eks.create_capability(**kwargs)
            return None
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            last_message = str(e)
            if last_code == "InvalidParameterException" and "trust policy" in last_message:
                time.sleep(delay_s)
                continue
            if refusal is not None:
                refusal["message"] = e.response["Error"].get("Message", "")
            return last_code
    return last_code


def _describe_capability_tolerating_lag(eks, cluster_name, capability_name, attempts=6, delay_s=10):
    # DescribeCapability right after CreateCapability can 404 until the record propagates.
    last_err = None
    for _ in range(attempts):
        try:
            return eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)["capability"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise AssertionError(f"describe_capability never became visible for {capability_name}: {last_err}")


#: Zone IDs EKS does not offer control-plane placement in.
_EKS_UNSUPPORTED_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _get_subnets(ctx) -> list[str]:
    """Up to three subnets of the run's shared network, in distinct EKS-supported zones."""
    subnets = ctx.network().subnets
    zones = ctx.client("ec2").describe_availability_zones(ZoneNames=sorted(subnets))["AvailabilityZones"]
    zone_ids = {z["ZoneName"]: z["ZoneId"] for z in zones}
    subnet_ids = [subnets[az] for az in sorted(subnets) if zone_ids[az] not in _EKS_UNSUPPORTED_AZS]
    assert len(subnet_ids) >= 2, f"need >=2 EKS-supported zones in the shared network, found {sorted(subnets)}"
    return subnet_ids[:3]


def _delete_capability_and_wait(eks, cluster_name, capability_name, timeout_s=900.0):
    """DeleteCapability is asynchronous, and DeleteCluster is refused while a capability is
    attached, so wait until the capability is gone."""
    try:
        eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"capability {capability_name} still present {timeout_s}s after DeleteCapability")


def _delete_cluster_and_wait(eks, name, timeout_s=900.0):
    """Delete the cluster (retrying while an update or capability still holds it) and wait until
    it is gone, so its network interfaces leave the shared network."""
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
        time.sleep(20)
    # The wait for the cluster to go gets a window of its own: a delete accepted late in the
    # retry window is not reported as a failure.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(20)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s}s after DeleteCluster")


def _poll_until(probe, predicate, timeout_s, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


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
                # CreateCapability needs access entries, which need authenticationMode API or
                # API_AND_CONFIG_MAP; the default CONFIG_MAP would fail every CreateCapability.
                accessConfig={"authenticationMode": "API"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, name))
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

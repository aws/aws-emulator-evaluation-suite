"""identity-provider-config-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-provider-config-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error_detail(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
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
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _create_cluster_when_role_propagated(c, name, role_arn, subnet_ids, timeout_s=120, interval_s=6):
    """create_cluster, retrying while IAM has not yet propagated the brand-new role.

    A fresh role can 400 with InvalidParameterException/ClientException for a few
    seconds after creation; bound the retry instead of guessing a fixed sleep.
    """
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            c.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": subnet_ids,
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
                tags={"sim2real": "1"},
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidParameterException", "ClientException"):
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"create_cluster {name} never accepted the role (IAM propagation?): {last_err}")


def _active_cluster(ctx, c, suffix):
    """Provision (create + wait ACTIVE) a throwaway cluster, register cleanup, return its name."""
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + suffix)
    _create_cluster_when_role_propagated(c, name, role_arn, _subnet_ids(ctx))
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster {name} landed in {cluster['status']!r}"
    return name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a fresh ACTIVE cluster, describe and disassociate of an absent OIDC config and associate onto an unknown
    cluster answer ResourceNotFoundException, and an http:// issuer InvalidParameterException, each with its exact
    message; the cluster stays ACTIVE with no identity provider config."""
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-idp-")
    initial = c.list_identity_provider_configs(clusterName=cluster)["identityProviderConfigs"]
    assert initial == [], f"expected no identity provider configs on a fresh cluster, got {initial!r}"

    absent = {"type": "oidc", "name": ctx.unique_name("oidc-")}
    not_found = "The requested resource does not exist."
    describe_code, describe_message = _error_detail(
        lambda: c.describe_identity_provider_config(clusterName=cluster, identityProviderConfig=absent)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing an absent config, got {describe_code!r}"
    )
    assert describe_message == not_found, f"expected message {not_found!r}, got {describe_message!r}"
    disassociate_code, disassociate_message = _error_detail(
        lambda: c.disassociate_identity_provider_config(clusterName=cluster, identityProviderConfig=absent)
    )
    assert disassociate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException disassociating an absent config, got {disassociate_code!r}"
    )
    assert disassociate_message == not_found, f"expected message {not_found!r}, got {disassociate_message!r}"

    absent_cluster = ctx.unique_name("absent-clu-")
    absent_cluster_code, absent_cluster_message = _error_detail(
        lambda: c.associate_identity_provider_config(
            clusterName=absent_cluster,
            oidc={
                "identityProviderConfigName": ctx.unique_name("oidc-"),
                "issuerUrl": "https://sim2real.example.com",
                "clientId": "sim2real",
            },
        )
    )
    assert absent_cluster_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException associating onto an unknown cluster, got {absent_cluster_code!r}"
    )
    expected = f"No cluster found for name: {absent_cluster}."
    assert absent_cluster_message == expected, f"expected message {expected!r}, got {absent_cluster_message!r}"

    non_tls_code, non_tls_message = _error_detail(
        lambda: c.associate_identity_provider_config(
            clusterName=cluster,
            oidc={
                "identityProviderConfigName": ctx.unique_name("oidc-"),
                "issuerUrl": "http://sim2real.example.com",
                "clientId": "sim2real",
            },
        )
    )
    assert non_tls_code == "InvalidParameterException", (
        f"expected InvalidParameterException for a non-TLS issuer URL, got {non_tls_code!r}"
    )
    expected = "IssuerURL must use https:// scheme."
    assert non_tls_message == expected, f"expected message {expected!r}, got {non_tls_message!r}"

    status = c.describe_cluster(name=cluster)["cluster"]["status"]
    assert status == "ACTIVE", f"expected the cluster to remain ACTIVE (no mutation happened), got {status!r}"
    final = c.list_identity_provider_configs(clusterName=cluster)["identityProviderConfigs"]
    assert final == [], f"expected no identity provider config to have been associated, got {final!r}"


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
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

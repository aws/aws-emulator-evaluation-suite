"""identity-provider-config-details-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-provider-config-details-round-trip"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OIDC identity provider config details (issuer URL, claim mappings) associated on a cluster
    come back unchanged, and are gone from both list and describe once disassociated."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    name = cluster["name"]
    # Must differ from the cluster's own built-in OIDC issuer (used for IRSA): EKS rejects
    # AssociateIdentityProviderConfig with InvalidParameterException when the external IdP's
    # issuerUrl is the same as the cluster's own issuer.
    issuer_url = "https://sim2real.example.com"

    config_name = ctx.unique_name("sim2real-oidc-")
    oidc_request = {
        "identityProviderConfigName": config_name,
        "issuerUrl": issuer_url,
        "clientId": "sts.amazonaws.com",
        "usernameClaim": "email",
        "groupsClaim": "cognito:groups",
        "usernamePrefix": "oidc:",
        "groupsPrefix": "oidc-group:",
    }
    update = eks.associate_identity_provider_config(clusterName=name, oidc=oidc_request)["update"]

    def _cleanup_idp():
        try:
            eks.disassociate_identity_provider_config(
                clusterName=name, identityProviderConfig={"type": "oidc", "name": config_name}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidRequestException"):
                raise

    ctx.on_cleanup(_cleanup_idp)
    _wait_for_update(ctx, name, update["id"])

    described = eks.describe_identity_provider_config(
        clusterName=name, identityProviderConfig={"type": "oidc", "name": config_name}
    )["identityProviderConfig"]["oidc"]

    assert described["issuerUrl"] == issuer_url, f"issuerUrl mutated: {described['issuerUrl']!r} != {issuer_url!r}"
    assert described["clientId"] == "sts.amazonaws.com", f"clientId mutated: {described['clientId']!r}"
    assert described["usernameClaim"] == "email", f"usernameClaim mutated: {described['usernameClaim']!r}"
    assert described["groupsClaim"] == "cognito:groups", f"groupsClaim mutated: {described['groupsClaim']!r}"
    assert described["usernamePrefix"] == "oidc:", f"usernamePrefix mutated: {described['usernamePrefix']!r}"
    assert described["groupsPrefix"] == "oidc-group:", f"groupsPrefix mutated: {described['groupsPrefix']!r}"

    disassociate_update = eks.disassociate_identity_provider_config(
        clusterName=name, identityProviderConfig={"type": "oidc", "name": config_name}
    )["update"]
    _wait_for_update(ctx, name, disassociate_update["id"])

    remaining = eks.list_identity_provider_configs(clusterName=name)["identityProviderConfigs"]
    assert not any(cfg["name"] == config_name for cfg in remaining), (
        f"{config_name} still listed after disassociate: {remaining}"
    )

    not_found = "The requested resource does not exist."
    try:
        eks.describe_identity_provider_config(
            clusterName=name, identityProviderConfig={"type": "oidc", "name": config_name}
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException describing a disassociated config, got {code!r}"
        )
        assert message == not_found, f"expected message {not_found!r}, got {message!r}"
    else:
        raise AssertionError(f"describe_identity_provider_config succeeded for disassociated config {config_name}")

    try:
        eks.disassociate_identity_provider_config(
            clusterName=name, identityProviderConfig={"type": "oidc", "name": config_name}
        )
    except ClientError as exc:
        redisassociate_code = exc.response["Error"]["Code"]
        redisassociate_message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"re-disassociating already-gone config {config_name} unexpectedly succeeded")
    assert redisassociate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-disassociating a gone config, got {redisassociate_code!r}"
    )
    assert redisassociate_message == not_found, (
        f"expected message {not_found!r}, got {redisassociate_message!r}"
    )


def _get_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision the EKS cluster prerequisite subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in >=2 availability zones for an EKS cluster")
    return list(by_az.values())[:3]


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
    deadline = time.monotonic() + 30.0
    while True:
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            if time.monotonic() >= deadline:
                raise AssertionError(f"role {role_name} did not become visible via get_role within 30s")
            time.sleep(2)
    return role["Arn"]


def _wait_for_cluster_active(ctx, name, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


def _delete_cluster_safe(ctx, name):
    eks = ctx.client("eks")
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = eks.describe_cluster(name=name)["cluster"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status not in ("CREATING", "UPDATING", "DELETING"):
            break
        time.sleep(15)
    _delete_eks_cluster_retrying(eks, name)


def _create_active_cluster(ctx, **extra_kwargs):
    eks = ctx.client("eks")
    subnets = _get_two_az_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnets},
        tags={"sim2real": "1"},
    )
    kwargs.update(extra_kwargs)
    deadline = time.monotonic() + 60.0
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:  # a just-created role can take a few seconds to propagate
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_safe(ctx, name))
    return _wait_for_cluster_active(ctx, name)


def _wait_for_update(ctx, cluster_name, update_id, timeout_s=600.0, interval_s=15.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster_name, updateId=update_id)["update"]
        status = update["status"]
        if status != "InProgress":
            if status != "Successful":
                raise AssertionError(f"update {update_id} ended in {status}: {update.get('errors')}")
            return update
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} did not complete within {timeout_s}s")



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

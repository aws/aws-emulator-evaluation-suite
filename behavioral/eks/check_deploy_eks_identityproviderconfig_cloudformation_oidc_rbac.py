"""deploy-eks-identityproviderconfig-cloudformation-oidc-rbac."""
from __future__ import annotations

import base64
import json
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eks-identityproviderconfig-cloudformation-oidc-rbac"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp", "eks"]

_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_CLUSTER_ACTIVE_TIMEOUT_S = 1200
_CLUSTER_DELETE_TIMEOUT_S = 900
_STACK_WAIT_DELAY_S = 2
_STACK_WAIT_ATTEMPTS = 900
_API_REACHABLE_TIMEOUT_S = 300
_TEST_PASSWORD = "Sim2Real-Oidc-Test9!"


def _trust(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_cluster_role(ctx, iam) -> str:
    """A per-run EKS cluster IAM role, detached and deleted at teardown."""
    name = ctx.unique_name("sim2real-eks-idp-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust("eks.amazonaws.com"),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_EKS_CLUSTER_POLICY))
    return arn


def _subnet_ids(ctx, ec2, count: int = 2) -> list[str]:
    """AZ-distinct subnets of the shared network VPC (account baseline)."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "this account has no shared network VPC (account baseline) to place the cluster in"
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= count, f"shared network has subnets in {len(by_az)} AZs, need {count}"
    return [by_az[az] for az in sorted(by_az)][:count]


def _wait_for(fn, pred, timeout_s: float, interval_s: float, desc: str):
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _cluster_gone(eks, name: str) -> bool:
    try:
        eks.describe_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _delete_cluster_and_wait(eks, name: str) -> None:
    deadline = time.monotonic() + _CLUSTER_DELETE_TIMEOUT_S
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    _wait_for(
        lambda: _cluster_gone(eks, name), bool, max(0.0, deadline - time.monotonic()), 10,
        f"cluster {name} deleted",
    )


def _create_cluster(ctx, eks, role_arn: str, subnet_ids: list[str]) -> dict:
    """A check-owned cluster with no managed nodes, polled to ACTIVE; its teardown is registered."""
    name = ctx.unique_name("sim2real-eks-idp-")
    deadline = time.monotonic() + 180
    while True:
        try:
            eks.create_cluster(
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
                tags={"sim2real-managed": "true"},
            )
            break
        except ClientError as exc:
            # IAM is eventually consistent: EKS rejects a brand-new role until it propagates.
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, name))
    cluster = _wait_for(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        _CLUSTER_ACTIVE_TIMEOUT_S, 15, f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", f"cluster {name} ended {cluster['status']!r}"
    assert cluster.get("endpoint"), f"ACTIVE cluster {name} publishes no API server endpoint"
    return cluster


def _create_oidc_identity(ctx, cognito) -> dict:
    """A Cognito user pool used as a publicly-discoverable OIDC provider, with one user who
    belongs to one group; its ID token carries a cognito:groups claim naming that group."""
    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-eks-idp-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-eks-idp-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    group_name = ctx.unique_name("sim2real-eks-idp-group-")
    cognito.create_group(UserPoolId=pool_id, GroupName=group_name)
    username = ctx.unique_name("sim2real-eks-idp-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=_TEST_PASSWORD, MessageAction="SUPPRESS"
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_TEST_PASSWORD, Permanent=True
    )
    cognito.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group_name)
    return {
        "pool_id": pool_id,
        "client_id": client_id,
        "issuer": f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}",
        "group": group_name,
        "username": username,
    }


def _id_token(cognito, identity: dict) -> str:
    resp = cognito.admin_initiate_auth(
        UserPoolId=identity["pool_id"],
        ClientId=identity["client_id"],
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": identity["username"], "PASSWORD": _TEST_PASSWORD},
    )
    return resp["AuthenticationResult"]["IdToken"]


def _idp_stack_template(cluster_name: str, config_name: str, identity: dict, extra_tags: dict) -> dict:
    tag_list = [{"Key": "sim2real-managed", "Value": "true"}]
    tag_list.extend({"Key": k, "Value": v} for k, v in extra_tags.items())
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "IdpConfig": {
                "Type": "AWS::EKS::IdentityProviderConfig",
                "Properties": {
                    "ClusterName": cluster_name,
                    "IdentityProviderConfigName": config_name,
                    "Type": "oidc",
                    "Oidc": {
                        "IssuerUrl": identity["issuer"],
                        "ClientId": identity["client_id"],
                        "UsernameClaim": "sub",
                        "GroupsClaim": "cognito:groups",
                    },
                    "Tags": tag_list,
                },
            }
        },
    }


def _wait_stack(cfn, stack_name: str, waiter_name: str) -> None:
    cfn.get_waiter(waiter_name).wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _STACK_WAIT_DELAY_S, "MaxAttempts": _STACK_WAIT_ATTEMPTS},
    )


def _stack_failure_reason(cfn, stack_name: str, logical_id: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for e in events:
        if e["LogicalResourceId"] == logical_id and e.get("ResourceStatusReason"):
            return e["ResourceStatusReason"]
    return "(no resource status reason found)"


def _delete_idp_config(eks, cluster_name: str, config_name: str) -> bool:
    try:
        eks.describe_identity_provider_config(
            clusterName=cluster_name, identityProviderConfig={"type": "oidc", "name": config_name}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _bearer_token(ctx, cluster_name: str) -> str:
    """The IAM-based EKS bearer token: a presigned STS GetCallerIdentity bound to the cluster
    name, used by the bootstrap cluster-creator admin identity to configure RBAC."""
    from botocore.signers import RequestSigner

    sts = ctx.client("sts")
    signer = RequestSigner(
        sts.meta.service_model.service_id, ctx.region, "sts", "v4",
        sts._request_signer._credentials, sts.meta.events,
    )
    url = signer.generate_presigned_url(
        {
            "method": "GET",
            "url": ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com")
            + "/?Action=GetCallerIdentity&Version=2011-06-15",
            "body": {},
            "headers": {"x-k8s-aws-id": cluster_name},
            "context": {},
        },
        region_name=ctx.region, expires_in=60, operation_name="",
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _kubeconfig(ctx, cluster: dict, token: str, path: str) -> None:
    """A kubeconfig for the cluster's published endpoint and CA, carrying a bearer token
    that is either the IAM presigned token or a plain OIDC ID token."""
    server = ctx.endpoint_url(cluster["endpoint"])
    entry: dict = {"server": server}
    if server.startswith("https://"):
        if ctx.http_verify is False:
            entry["insecure-skip-tls-verify"] = True
        else:
            pem = base64.b64decode((cluster.get("certificateAuthority") or {}).get("data") or "")
            if isinstance(ctx.http_verify, str):
                with open(ctx.http_verify, "rb") as fh:
                    pem = pem.rstrip(b"\n") + b"\n" + fh.read()
            if pem:
                entry["certificate-authority-data"] = base64.b64encode(pem).decode()
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "c", "cluster": entry}],
        "users": [{"name": "u", "user": {"token": token}}],
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "current-context": "ctx",
    }
    with open(path, "w") as fh:
        json.dump(config, fh)  # JSON is valid YAML, which kubectl reads


DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _kubectl(args: list[str], env: dict, timeout: float = 60):
    import subprocess

    return subprocess.run(["kubectl", *args], env=env, capture_output=True, text=True, timeout=timeout)


def _run_cli(args: list[str], env: dict, timeout: float = 60) -> str:
    proc = _kubectl(args, env, timeout)
    if proc.returncode != 0:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: command failed (rc={proc.returncode}): kubectl {' '.join(args)}\n"
            f"  stderr: {proc.stderr[-500:]}"
        )
    return proc.stdout


def _wait_api_reachable(env: dict) -> None:
    deadline = time.monotonic() + _API_REACHABLE_TIMEOUT_S
    while True:
        proc = _kubectl(["get", "namespaces", "-o", "name"], env, timeout=30)
        if proc.returncode == 0:
            return
        s = proc.stderr.lower()
        transient = "no such host" in s or "i/o timeout" in s or "connection refused" in s
        if not transient or time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: command failed (rc={proc.returncode}): kubectl get namespaces\n"
                f"  stderr: {proc.stderr[-500:]}"
            )
        time.sleep(5)


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "dp:native",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::EKS::IdentityProviderConfig from CloudFormation makes the cluster trust an OIDC
    issuer: a token from it authenticates and its RBAC-bound group governs what it may do.
    A tag update applies in place, and deleting the stack removes the association.
    """
    from fidelity_tests_runner import require_tools

    require_tools("kubectl")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")
    cognito = ctx.client("cognito-idp")

    subnet_ids = _subnet_ids(ctx, ec2)
    cluster_role_arn = _create_cluster_role(ctx, iam)
    cluster = _create_cluster(ctx, eks, cluster_role_arn, subnet_ids)
    cluster_name = cluster["name"]

    identity = _create_oidc_identity(ctx, cognito)

    config_name = ctx.unique_name("sim2real-eks-idp-cfg-")
    stack_name = ctx.unique_name("sim2real-eks-idp-stack-")

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        _wait_stack(cfn, stack_name, "stack_delete_complete")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_idp_stack_template(cluster_name, config_name, identity, {})),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )
    ctx.on_cleanup(_delete_stack)
    try:
        _wait_stack(cfn, stack_name, "stack_create_complete")
    except Exception:
        reason = _stack_failure_reason(cfn, stack_name, "IdpConfig")
        raise AssertionError(f"IdentityProviderConfig stack create failed: {reason}")

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {stack['StackStatus']!r}"

    desc = eks.describe_identity_provider_config(
        clusterName=cluster_name, identityProviderConfig={"type": "oidc", "name": config_name}
    )["identityProviderConfig"]["oidc"]
    assert desc["issuerUrl"] == identity["issuer"], f"issuerUrl read back as {desc['issuerUrl']!r}"
    assert desc["clientId"] == identity["client_id"], f"clientId read back as {desc['clientId']!r}"
    assert desc["usernameClaim"] == "sub", f"usernameClaim read back as {desc['usernameClaim']!r}"
    assert desc["groupsClaim"] == "cognito:groups", f"groupsClaim read back as {desc['groupsClaim']!r}"
    assert desc["status"] == "ACTIVE", f"identity provider config status was {desc['status']!r}"
    assert desc.get("identityProviderConfigArn"), "ACTIVE config published no ARN"
    first_arn = desc["identityProviderConfigArn"]

    # Exercise the data plane: bind the OIDC group to the built-in read-only ClusterRole, then
    # authenticate as the Cognito user and prove both that the token is trusted and that RBAC
    # (not a blanket allow) governs what it can do.
    admin_env = ctx.subprocess_env()
    admin_kcfg = tempfile.NamedTemporaryFile(prefix="sim2real-kubeconfig-admin-", suffix=".yaml", delete=False)
    admin_kcfg.close()
    ctx.on_cleanup(lambda: __import__("os").unlink(admin_kcfg.name))
    _kubeconfig(ctx, cluster, _bearer_token(ctx, cluster_name), admin_kcfg.name)
    admin_env["KUBECONFIG"] = admin_kcfg.name
    _wait_api_reachable(admin_env)

    binding_name = ctx.unique_name("sim2real-eks-idp-crb-")
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": binding_name},
        "subjects": [{"kind": "Group", "name": identity["group"], "apiGroup": "rbac.authorization.k8s.io"}],
        "roleRef": {"kind": "ClusterRole", "name": "view", "apiGroup": "rbac.authorization.k8s.io"},
    }
    binding_file = tempfile.NamedTemporaryFile(
        prefix="sim2real-crb-", suffix=".json", mode="w", delete=False
    )
    json.dump(binding, binding_file)
    binding_file.close()
    ctx.on_cleanup(lambda: __import__("os").unlink(binding_file.name))
    _run_cli(["apply", "-f", binding_file.name], admin_env)

    def _delete_binding():
        proc = _kubectl(["delete", "clusterrolebinding", binding_name], admin_env, timeout=60)
        if proc.returncode != 0 and "notfound" not in proc.stderr.lower().replace(" ", ""):
            raise AssertionError(f"failed to delete ClusterRoleBinding {binding_name}: {proc.stderr}")

    ctx.on_cleanup(_delete_binding)

    oidc_env = dict(admin_env)
    oidc_kcfg = tempfile.NamedTemporaryFile(prefix="sim2real-kubeconfig-oidc-", suffix=".yaml", delete=False)
    oidc_kcfg.close()
    ctx.on_cleanup(lambda: __import__("os").unlink(oidc_kcfg.name))
    _kubeconfig(ctx, cluster, _id_token(cognito, identity), oidc_kcfg.name)
    oidc_env["KUBECONFIG"] = oidc_kcfg.name

    # Positive control: the OIDC token authenticates and "view" lets it list ConfigMaps.
    deadline = time.monotonic() + 120
    last_err = ""
    while True:
        proc = _kubectl(["get", "configmaps", "-n", "default", "-o", "name"], oidc_env, timeout=30)
        if proc.returncode == 0:
            break
        last_err = proc.stderr
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"OIDC-authenticated kubectl get configmaps never succeeded: {last_err[-500:]}"
            )
        time.sleep(5)

    # The same wiring refuses a write the "view" ClusterRole does not grant.
    proc = _kubectl(
        ["create", "configmap", ctx.unique_name("sim2real-eks-idp-cm-"), "-n", "default", "--from-literal=a=b"],
        oidc_env, timeout=30,
    )
    assert proc.returncode != 0 and "forbidden" in proc.stderr.lower(), (
        f"expected the view-bound OIDC identity's create to be Forbidden, got "
        f"rc={proc.returncode} stderr={proc.stderr[-300:]!r}"
    )

    # Update in place: Tags is mutable, so adding one must not replace the resource (same ARN).
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(
            _idp_stack_template(cluster_name, config_name, identity, {"sim2real-extra": "updated"})
        ),
    )
    _wait_stack(cfn, stack_name, "stack_update_complete")
    desc2 = eks.describe_identity_provider_config(
        clusterName=cluster_name, identityProviderConfig={"type": "oidc", "name": config_name}
    )["identityProviderConfig"]["oidc"]
    assert desc2["identityProviderConfigArn"] == first_arn, (
        f"a Tags-only update replaced the resource: ARN was {first_arn!r}, now {desc2['identityProviderConfigArn']!r}"
    )
    assert desc2.get("tags", {}).get("sim2real-extra") == "updated", (
        f"expected tag sim2real-extra=updated after in-place update, got tags={desc2.get('tags')!r}"
    )

    # Delete the stack and prove the association is gone, not merely the CloudFormation record.
    _delete_stack()
    gone_after_delete = _wait_for(
        lambda: _delete_idp_config(eks, cluster_name, config_name), bool, 300, 10,
        f"identity provider config {config_name} disassociated after stack delete",
    )
    assert gone_after_delete, f"identity provider config {config_name} still present after stack delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

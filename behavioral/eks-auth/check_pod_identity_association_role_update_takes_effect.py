"""pod-identity-association-role-update-takes-effect."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-role-update-takes-effect"
GROUP = "state"
SERVICES = ["eks-auth"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """State transition: updating a Pod Identity association's roleArn causes subsequent
    AssumeRoleForPodIdentity calls for that identity to assume the NEW role, not the original
    one -- the update actually propagates to the eks-auth data plane."""
    cluster_name, endpoint, ca_data = _create_eks_cluster(ctx)
    role_arn_1, association = _create_pod_identity_association(ctx, cluster_name, "default", "default")
    role_arn_2, _role_name_2 = _iam_role_for_pod_identity(ctx)
    eks = ctx.client("eks")
    eks_auth = ctx.client("eks-auth")

    # AssumeRoleForPodIdentity rejects a ServiceAccount token with no `kubernetes.io/pod` claim
    # (InvalidTokenException: "missing required claim"), so the TokenRequest must bind to a real
    # Pod object -- exactly what the kubelet's own projected-volume token request does.
    pod_name, pod_uid = _create_bound_pod(ctx, cluster_name, endpoint, ca_data, "default", "default")
    bound_pod = {"name": pod_name, "uid": pod_uid}

    token_1 = _get_service_account_token(
        ctx, cluster_name, endpoint, ca_data, "default", "default", bound_pod=bound_pod
    )

    def _assume(token):
        return eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=token)

    first = _retry_client_error(
        lambda: _assume(token_1),
        # Both codes are the documented propagation window right after CreatePodIdentity-
        # Association: InvalidRequestException before the association itself is visible, and
        # AccessDeniedException ("EKS does not have permissions to assume the associated role")
        # before the role's freshly-created trust policy has propagated through IAM.
        retry_codes=("InvalidRequestException", "AccessDeniedException"),
        attempts=12,
        delay=5,
    )
    # An STS assumed-role ARN swaps BOTH the service segment (iam -> sts) and the resource type
    # (role/ -> assumed-role/), not just the resource type.
    expected_prefix_1 = role_arn_1.replace(":iam:", ":sts:").replace(":role/", ":assumed-role/")
    assert first["assumedRoleUser"]["arn"].startswith(expected_prefix_1), (
        f"expected assumed role arn to start with {expected_prefix_1!r}, "
        f"got {first['assumedRoleUser']['arn']!r}"
    )

    eks.update_pod_identity_association(
        clusterName=cluster_name, associationId=association["associationId"], roleArn=role_arn_2
    )

    expected_prefix = role_arn_2.replace(":iam:", ":sts:").replace(":role/", ":assumed-role/")
    deadline = time.time() + 90
    second = None
    while time.time() < deadline:
        token_n = _get_service_account_token(
            ctx, cluster_name, endpoint, ca_data, "default", "default", bound_pod=bound_pod
        )
        try:
            candidate = _assume(token_n)
        except ClientError:
            candidate = None
        if candidate is not None and candidate["assumedRoleUser"]["arn"].startswith(expected_prefix):
            second = candidate
            break
        time.sleep(5)

    assert second is not None, "association update to a new roleArn never took effect"
    assert second["assumedRoleUser"]["arn"].startswith(expected_prefix), (
        f"expected assumed role arn to start with {expected_prefix!r}, "
        f"got {second['assumedRoleUser']['arn']!r}"
    )
    assert second["podIdentityAssociation"]["associationId"] == association["associationId"], (
        f"expected associationId {association['associationId']!r}, "
        f"got {second['podIdentityAssociation']['associationId']!r}"
    )


# ===== shared helpers =====
def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _retry_client_error(fn, retry_codes, attempts=12, delay=5):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in retry_codes:
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    raise last_exc


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; provisioning a dedicated VPC just for this "
            "native pod-identity round trip is out of scope for a single check"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span at least two availability zones")
    return subnet_ids[:3]


def _iam_role_for_eks_cluster(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eksa-clusrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _iam_role_for_pod_identity(ctx, inline_policy=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eksa-podrole-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_policy is not None:
        iam.put_role_policy(RoleName=role_name, PolicyName="test-policy", PolicyDocument=json.dumps(inline_policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="test-policy"))
    return role_arn, role_name


def _create_eks_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids = _default_vpc_subnets(ctx)
    cluster_name = ctx.unique_name("sim2real-eksauth-")
    role_arn = _iam_role_for_eks_cluster(ctx)

    def _create():
        eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={
                "subnetIds": subnet_ids,
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            tags={"sim2real": CHECK},
        )

    _retry_client_error(_create, retry_codes=("InvalidParameterException",))
    ctx.on_cleanup(lambda: _delete_eks_cluster(ctx, cluster_name))
    eks.get_waiter("cluster_active").wait(name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    desc = eks.describe_cluster(name=cluster_name)["cluster"]
    return cluster_name, ctx.endpoint_url(desc["endpoint"]), desc["certificateAuthority"]["data"]


def _delete_eks_cluster(ctx, cluster_name):
    eks = ctx.client("eks")
    eks.delete_cluster(name=cluster_name)
    eks.get_waiter("cluster_deleted").wait(name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 360})


def _create_pod_identity_association(ctx, cluster_name, namespace, service_account, inline_policy=None):
    eks = ctx.client("eks")
    role_arn, _role_name = _iam_role_for_pod_identity(ctx, inline_policy=inline_policy)

    def _create():
        return eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn=role_arn,
            tags={"sim2real": CHECK},
        )

    resp = _retry_client_error(_create, retry_codes=("InvalidParameterException",))
    association = resp["association"]
    ctx.on_cleanup(
        lambda: eks.delete_pod_identity_association(
            clusterName=cluster_name, associationId=association["associationId"]
        )
    )
    return role_arn, association


def _eks_k8s_bearer_token(ctx, cluster_name):
    sts = ctx.client("sts")
    signer = sts._request_signer
    request_dict = {
        "method": "GET",
        "url": ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com") + "/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed_url = signer.generate_presigned_url(
        request_dict, region_name=ctx.region, expires_in=60, operation_name="GetCallerIdentity"
    )
    encoded = base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode("utf-8").rstrip("=")
    return "k8s-aws-v1." + encoded


def _k8s_api_request(endpoint, ca_data_b64, bearer_token, method, path, body=None):
    ca_pem = base64.b64decode(ca_data_b64).decode("utf-8")
    ssl_ctx = ssl.create_default_context(cadata=ca_pem)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(endpoint.rstrip("/") + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {bearer_token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_service_account_token(
    ctx,
    cluster_name,
    endpoint,
    ca_data_b64,
    namespace,
    sa_name,
    audiences=("pods.eks.amazonaws.com",),
    expiration_seconds=600,
    bound_pod=None,
):
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    spec = {"audiences": list(audiences), "expirationSeconds": expiration_seconds}
    if bound_pod is not None:
        spec["boundObjectRef"] = {
            "apiVersion": "v1",
            "kind": "Pod",
            "name": bound_pod["name"],
            "uid": bound_pod["uid"],
        }
    body = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": spec,
    }
    path = f"/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token"
    resp = _k8s_api_request(endpoint, ca_data_b64, bearer, "POST", path, body=body)
    return resp["status"]["token"]


def _create_bound_pod(ctx, cluster_name, endpoint, ca_data_b64, namespace, sa_name):
    """Create a real Pod object for the TokenRequest's boundObjectRef to reference.

    The cluster has no nodegroup, so the pod stays Pending forever -- irrelevant here, since
    the API server assigns a UID at object-creation time, before any scheduling happens."""
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    pod_name = ctx.unique_name("sim2real-podid-")
    body = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "labels": {"sim2real": CHECK}},
        "spec": {
            "serviceAccountName": sa_name,
            "containers": [{"name": "sim2real", "image": "public.ecr.aws/eks-distro/kubernetes/pause:3.9"}],
        },
    }
    path = f"/api/v1/namespaces/{namespace}/pods"
    resp = _k8s_api_request(endpoint, ca_data_b64, bearer, "POST", path, body=body)
    ctx.on_cleanup(lambda: _delete_bound_pod(ctx, cluster_name, endpoint, ca_data_b64, namespace, pod_name))
    return resp["metadata"]["name"], resp["metadata"]["uid"]


def _delete_bound_pod(ctx, cluster_name, endpoint, ca_data_b64, namespace, pod_name):
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    path = f"/api/v1/namespaces/{namespace}/pods/{pod_name}"
    _k8s_api_request(endpoint, ca_data_b64, bearer, "DELETE", path)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

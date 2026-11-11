"""pod-identity-wrong-audience-token-rejected."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-wrong-audience-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A valid service account token minted for an audience other than "pods.eks.amazonaws.com" is
    rejected with InvalidTokenException; a token for the correct audience bound to the SAME pod
    succeeds, so audience is the only difference between them."""
    cluster_name, endpoint, ca_data = _create_eks_cluster(ctx)
    role_arn, _association = _create_pod_identity_association(ctx, cluster_name, "default", "default")
    eks_auth = ctx.client("eks-auth")
    pod_name, pod_uid = _create_pod(ctx, cluster_name, endpoint, ca_data, "default", "default")

    wrong_aud_token = _get_service_account_token(
        ctx, cluster_name, endpoint, ca_data, "default", "default",
        audiences=("sts.amazonaws.com",), bound_pod=(pod_name, pod_uid),
    )
    code, message = _client_error(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=wrong_aud_token)
    )
    assert code == "InvalidTokenException", (
        f"a validly-signed token minted for this cluster with audience 'sts.amazonaws.com' "
        f"(not 'pods.eks.amazonaws.com') returned {code!r}, expected 'InvalidTokenException'"
    )
    assert message == _WRONG_AUDIENCE_MESSAGE, (
        f"EXPECTED_MESSAGE={_WRONG_AUDIENCE_MESSAGE!r} GOT={message!r}"
    )

    # Positive control: same bound pod, correct audience, succeeds.
    good_token = _get_service_account_token(
        ctx, cluster_name, endpoint, ca_data, "default", "default", bound_pod=(pod_name, pod_uid)
    )

    def _assume():
        return eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=good_token)

    resp = _retry_client_error(
        _assume, retry_codes=("InvalidRequestException", "AccessDeniedException"), attempts=12, delay=5
    )
    # An assumed-role ARN lives under the sts service namespace, not iam -- measured against
    # real AWS: a role ARN "arn:aws:iam::ACCOUNT:role/NAME" assumes to
    # "arn:aws:sts::ACCOUNT:assumed-role/NAME/SESSION", not "arn:aws:iam::...:assumed-role/...".
    expected_prefix = role_arn.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/")
    assert resp["assumedRoleUser"]["arn"].startswith(expected_prefix), (
        f"positive control: a correctly-audienced token for the same identity failed to "
        f"assume the pod identity role; got assumedRoleUser.arn={resp['assumedRoleUser']['arn']!r}, "
        f"expected it to start with {expected_prefix!r}"
    )

    # Effect absent: the wrong-audience token remains rejected on a second attempt, not
    # partially accepted/cached from the first call.
    code2, message2 = _client_error(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=wrong_aud_token)
    )
    assert code2 == "InvalidTokenException", (
        f"the wrong-audience token was rejected as 'InvalidTokenException' on the first "
        f"attempt but returned {code2!r} on a second, identical attempt; expected the "
        f"identical rejection again -- no partial acceptance or caching"
    )
    assert message2 == _WRONG_AUDIENCE_MESSAGE, (
        f"second attempt: EXPECTED_MESSAGE={_WRONG_AUDIENCE_MESSAGE!r} GOT={message2!r}"
    )


# ===== shared helpers =====
_WRONG_AUDIENCE_MESSAGE = (
    "The token included in the request has an invalid claim value for aud. Expected pods.eks.amazonaws.com."
)


def _client_error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target minting credentials for a token real AWS rejects is the strongest
    signal available and must not be reduced to an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected AssumeRoleForPodIdentity to reject this token, but it SUCCEEDED and "
        f"returned {sorted(result)!r}"
    )


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
            tags={"sim2real-check": CHECK},
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
            tags={"sim2real-check": CHECK},
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


def _create_pod(ctx, cluster_name, endpoint, ca_data_b64, namespace, sa_name):
    """Create a real (never-scheduled, since this cluster has no nodegroup) Pod object so a
    TokenRequest can bind to it -- AssumeRoleForPodIdentity requires the "kubernetes.io/pod"
    claim, which Kubernetes only stamps onto a token whose boundObjectRef names an existing Pod.
    Returns (name, uid). No explicit cleanup: it disappears with the cluster."""
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    pod_name = ctx.unique_name("sim2real-eksa-pod-")
    body = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace},
        "spec": {
            "serviceAccountName": sa_name,
            "containers": [{"name": "sim2real-placeholder", "image": "public.ecr.aws/eks-distro/kubernetes/pause:3.9"}],
        },
    }
    path = f"/api/v1/namespaces/{namespace}/pods"
    resp = _k8s_api_request(endpoint, ca_data_b64, bearer, "POST", path, body=body)
    return resp["metadata"]["name"], resp["metadata"]["uid"]


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
        pod_name, pod_uid = bound_pod
        spec["boundObjectRef"] = {"kind": "Pod", "apiVersion": "v1", "name": pod_name, "uid": pod_uid}
    body = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": spec,
    }
    path = f"/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token"
    resp = _k8s_api_request(endpoint, ca_data_b64, bearer, "POST", path, body=body)
    return resp["status"]["token"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

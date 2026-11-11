"""pod-identity-credentials-scoped-to-role-permissions-rejected."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-credentials-scoped-to-role-permissions-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """AssumeRoleForPodIdentity credentials carry exactly the pod role's permissions, not the
    caller's: the one granted action succeeds and an ungranted action is denied."""
    cluster_name, endpoint, ca_data = _create_eks_cluster(ctx)
    narrow_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "cloudwatch:ListMetrics", "Resource": "*"}],
    }
    _role_arn, _association = _create_pod_identity_association(
        ctx, cluster_name, "default", "default", inline_policy=narrow_policy
    )
    token = _get_service_account_token(ctx, cluster_name, endpoint, ca_data, "default", "default")
    eks_auth = ctx.client("eks-auth")

    def _assume():
        return eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=token)

    # Newly-created pod-identity roles/trust-policies take a few seconds to propagate through IAM;
    # real AWS answers with AccessDeniedException ("EKS does not have permissions to assume the
    # associated role") during that window, not with the InvalidRequestException the association
    # itself is documented to bounce -- both are transient asynchrony on a role this check just
    # created, not a rejection of anything under test here.
    resp = _retry_client_error(
        _assume, retry_codes=("InvalidRequestException", "AccessDeniedException"), attempts=24, delay=5
    )
    creds = resp["credentials"]
    borrowed = {
        "aws_access_key_id": creds["accessKeyId"],
        "aws_secret_access_key": creds["secretAccessKey"],
        "aws_session_token": creds["sessionToken"],
    }

    # Granted action succeeds.
    ctx.client("cloudwatch", creds=borrowed).list_metrics()

    # Ungranted action is rejected: the pod-identity credentials do not inherit whatever
    # broader IAM permissions the ctx test caller has in this account.
    iam_borrowed = ctx.client("iam", creds=borrowed)
    code, message = _client_error(lambda: iam_borrowed.list_roles())
    assert code == "AccessDenied", f"expected AccessDenied for an ungranted action, got {code!r}"
    session_arn = resp["assumedRoleUser"]["arn"]
    account = session_arn.split(":")[4]
    expected = (
        f"User: {session_arn} is not authorized to perform: iam:ListRoles on resource: "
        f"arn:aws:iam::{account}:role/ because no identity-based policy allows the iam:ListRoles action"
    )
    assert message == expected, f"EXPECTED_MESSAGE={expected!r} GOT={message!r}"


# ===== shared helpers =====
def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    turning acceptance into a falsy sentinel would let an over-permissive target read as
    merely the wrong error code instead of as the scoping failure it actually is."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be denied, but it SUCCEEDED and returned {result!r}")


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
            clusterName=cluster_name, namespace=namespace, serviceAccount=service_account, roleArn=role_arn
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
        "url": f"{sts.meta.endpoint_url}/?Action=GetCallerIdentity&Version=2011-06-15",
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


def _create_bound_pod(ctx, endpoint, ca_data_b64, bearer, namespace, sa_name):
    """AssumeRoleForPodIdentity requires the token's `kubernetes.io/pod` claim, which the API
    server only embeds when the TokenRequest carries a boundObjectRef pointing at a real Pod
    object -- a plain service-account TokenRequest has no such claim. The pod never needs a
    node (this cluster has none); it only needs to exist so its uid resolves."""
    pod_name = ctx.unique_name("sim2real-pod-")
    pods_path = f"/api/v1/namespaces/{namespace}/pods"
    body = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace},
        "spec": {
            "serviceAccountName": sa_name,
            "containers": [
                {"name": "sim2real", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "command": ["sleep", "3600"]}
            ],
            "restartPolicy": "Never",
        },
    }
    resp = _k8s_api_request(endpoint, ca_data_b64, bearer, "POST", pods_path, body=body)
    pod_uid = resp["metadata"]["uid"]
    ctx.on_cleanup(lambda: _k8s_api_request(endpoint, ca_data_b64, bearer, "DELETE", f"{pods_path}/{pod_name}"))
    return pod_name, pod_uid


def _get_service_account_token(
    ctx,
    cluster_name,
    endpoint,
    ca_data_b64,
    namespace,
    sa_name,
    audiences=("pods.eks.amazonaws.com",),
    expiration_seconds=600,
):
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    pod_name, pod_uid = _create_bound_pod(ctx, endpoint, ca_data_b64, bearer, namespace, sa_name)
    body = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "audiences": list(audiences),
            "expirationSeconds": expiration_seconds,
            "boundObjectRef": {"kind": "Pod", "apiVersion": "v1", "name": pod_name, "uid": pod_uid},
        },
    }
    path = f"/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token"
    resp = _k8s_api_request(endpoint, ca_data_b64, bearer, "POST", path, body=body)
    return resp["status"]["token"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

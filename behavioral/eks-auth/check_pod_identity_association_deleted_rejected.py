"""pod-identity-association-deleted-rejected."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-association-deleted-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Deleting a Pod Identity association cuts off its eks-auth data-plane identity: the next
    AssumeRoleForPodIdentity gets the same ResourceNotFoundException an identity that never had
    one gets; the deleted association is unreadable, unusable by id, and reusable by re-associating."""
    cluster_name, endpoint, ca_data = _create_eks_cluster(ctx)
    eks = ctx.client("eks")
    eks_auth = ctx.client("eks-auth")

    role_arn, association = _create_pod_identity_association(
        ctx, cluster_name, "default", "default", register_cleanup=False
    )
    association_id = association["associationId"]

    # AssumeRoleForPodIdentity rejects any token lacking a "kubernetes.io/pod" claim with
    # InvalidTokenException, regardless of association state -- a plain ServiceAccount
    # TokenRequest (no boundObjectRef) can never carry that claim, so it can never reach the
    # association-lookup logic this check exists to exercise. A real kubelet gets the claim by
    # binding the token to the Pod it is running in; this check gets the identical claim by
    # binding a TokenRequest to a throwaway Pod OBJECT -- deliberately unschedulable (no node
    # group or Fargate profile exists on this cluster), so it costs nothing and never runs, but
    # its mere existence (and UID) is all boundObjectRef needs.
    pod_name, pod_uid = _create_bound_pod(ctx, cluster_name, endpoint, ca_data, "default", "default")

    def _assume():
        token = _bound_service_account_token(ctx, cluster_name, endpoint, ca_data, "default", "default", pod_name, pod_uid)
        return eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=token)

    # (1) Positive control: the association works before we touch it.
    # A just-created role's trust policy can lag IAM's own propagation by a few seconds, which
    # eks-auth surfaces as AccessDeniedException rather than a not-found -- retry it exactly like
    # the "no association yet" case, not a distinct failure mode.
    before = _retry_client_error(
        _assume, retry_codes=("InvalidRequestException", "AccessDeniedException"), attempts=12, delay=5
    )
    expected_prefix = _assumed_role_arn_prefix(role_arn)
    assert before["assumedRoleUser"]["arn"].startswith(expected_prefix), (
        f"positive control did not assume {role_arn!r}: {before['assumedRoleUser']['arn']!r}"
    )

    # (2) Break exactly one thing: delete the association, nothing else.
    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)

    # (3) The specific rejection -- measured on real AWS to be ResourceNotFoundException.
    # eks-auth may cache the association briefly, so this is a bounded
    # retry, not a sleep: a success inside the window means the cache has not expired yet.
    deadline = time.time() + 90
    code = status = message = None
    while time.time() < deadline:
        try:
            _assume()
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code == "ResourceNotFoundException":
                break
        else:
            code = status = message = None
        time.sleep(5)
    assert code == "ResourceNotFoundException", f"GOT={code!r} after deleting the association"
    # The eks-auth model declares ResourceNotFoundException as HTTP 404.
    assert status == 404, (
        f"expected HTTP 404 from AssumeRoleForPodIdentity after the delete, got {status}"
    )
    # Same exact message as a token that never had an association in the first place: the delete
    # leaves no trace distinguishing "never associated" from "associated, then deleted".
    assert message == _NO_ASSOCIATION_MESSAGE, f"expected the message {_NO_ASSOCIATION_MESSAGE!r}, got {message!r}"

    # Gone beat 1: the association read by id is refused with the specific not-found code.
    dead_code, dead_status, message = _error(
        lambda: eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    )
    assert dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing the deleted association, got {dead_code}"
    )
    assert dead_status == 404, f"expected HTTP 404 describing the deleted association, got {dead_status}"
    expected_message = f"No service account role association found for ID: {association_id}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # (4) Effect absent via an independent read (eks:ListPodIdentityAssociations, not eks-auth).
    remaining = eks.list_pod_identity_associations(clusterName=cluster_name, namespace="default")["associations"]
    assert not any(a["associationId"] == association_id for a in remaining), (
        f"deleted association {association_id!r} still listed: {remaining!r}"
    )
    # Gone beat 3: a mutation on the dead id is refused the same way.
    dead_code, dead_status, message = _error(
        lambda: eks.update_pod_identity_association(
            clusterName=cluster_name, associationId=association_id, roleArn=role_arn
        )
    )
    assert dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating the deleted association, got {dead_code}"
    )
    assert dead_status == 404, f"expected HTTP 404 updating the deleted association, got {dead_status}"
    expected_message = f"No service account role association found for ID: {association_id}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # (5) Restore: the identifier (namespace/serviceAccount pair) is reusable -- re-associate it
    # with the same role.
    def _recreate():
        return eks.create_pod_identity_association(
            clusterName=cluster_name, namespace="default", serviceAccount="default", roleArn=role_arn
        )

    new_association = _retry_client_error(_recreate, retry_codes=("InvalidParameterException",))["association"]
    ctx.on_cleanup(lambda: _delete_association_if_present(eks, cluster_name, new_association["associationId"]))

    # (6) The identical call now succeeds again, against the SAME role.
    after = _retry_client_error(
        _assume,
        retry_codes=("InvalidRequestException", "AccessDeniedException", "ResourceNotFoundException"),
        attempts=12,
        delay=5,
    )
    assert after["assumedRoleUser"]["arn"].startswith(expected_prefix), (
        f"re-associated identity did not resume assuming {role_arn!r}: {after['assumedRoleUser']['arn']!r}"
    )


_NO_ASSOCIATION_MESSAGE = "The token included in the request has no service account role association for it."


def _assumed_role_arn_prefix(role_arn: str) -> str:
    """The Arn STS actually returns for an assumed role is service "sts", not "iam" -- measured
    on real AWS (an assume that returns 'arn:aws:iam::...:assumed-role/...' is not what
    AssumeRoleForPodIdentity gave back; it gave 'arn:aws:sts::...:assumed-role/<role>/<session>')."""
    return role_arn.replace("arn:aws:iam::", "arn:aws:sts::").replace(":role/", ":assumed-role/")


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "Name", "Value": role_name}, {"Key": "sim2real", "Value": "true"}],
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
        Tags=[{"Key": "Name", "Value": role_name}, {"Key": "sim2real", "Value": "true"}],
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
            tags={"Name": cluster_name, "sim2real": "true"},
        )

    _retry_client_error(_create, retry_codes=("InvalidParameterException",))
    ctx.on_cleanup(lambda: _delete_eks_cluster(ctx, cluster_name))
    eks.get_waiter("cluster_active").wait(name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    desc = eks.describe_cluster(name=cluster_name)["cluster"]
    return cluster_name, desc["endpoint"], desc["certificateAuthority"]["data"]


def _delete_eks_cluster(ctx, cluster_name):
    eks = ctx.client("eks")
    eks.delete_cluster(name=cluster_name)
    eks.get_waiter("cluster_deleted").wait(name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 360})


def _create_pod_identity_association(ctx, cluster_name, namespace, service_account, inline_policy=None, register_cleanup=True):
    eks = ctx.client("eks")
    role_arn, _role_name = _iam_role_for_pod_identity(ctx, inline_policy=inline_policy)

    def _create():
        return eks.create_pod_identity_association(
            clusterName=cluster_name, namespace=namespace, serviceAccount=service_account, roleArn=role_arn
        )

    resp = _retry_client_error(_create, retry_codes=("InvalidParameterException",))
    association = resp["association"]
    if register_cleanup:
        ctx.on_cleanup(lambda: _delete_association_if_present(eks, cluster_name, association["associationId"]))
    return role_arn, association


def _delete_association_if_present(eks, cluster_name, association_id):
    try:
        eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _ssl_context(ctx, ca_data_b64):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    ssl_ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    if ca_data_b64:
        ssl_ctx.load_verify_locations(cadata=base64.b64decode(ca_data_b64).decode("utf-8"))
    return ssl_ctx


def _k8s_api_request(ctx, endpoint, ca_data_b64, bearer_token, method, path, body=None):
    """One Kubernetes API call to the cluster's published endpoint, reached on the target.

    The Kubernetes API itself is the prerequisite eks/eks-kubectl-namespace proves. The published
    cluster CA is trusted (as kubectl is told to), plus the run's own CA bundle when
    ctx.http_verify names one; a run without verification skips it."""
    ssl_ctx = _ssl_context(ctx, ca_data_b64)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(ctx.endpoint_url(endpoint).rstrip("/") + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {bearer_token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _k8s_call(ctx, endpoint, ca_data_b64, bearer_token, method, path, body=None):
    """_k8s_api_request, with an HTTP refusal reported as an assertion naming the call."""
    try:
        return _k8s_api_request(ctx, endpoint, ca_data_b64, bearer_token, method, path, body=body)
    except urllib.error.HTTPError as exc:
        raise AssertionError(
            f"the cluster's Kubernetes API answered {method} {path} with HTTP {exc.code}: "
            f"{exc.read()[:300]!r}"
        ) from exc
    except (urllib.error.URLError, OSError) as exc:
        # Nothing answered at the published endpoint: the cluster has no Kubernetes API, so the
        # bound service-account token the eks-auth data plane consumes cannot be minted at all.
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: the cluster's Kubernetes API at {endpoint} could not be "
            f"reached for {method} {path} ({exc!r})"
        ) from exc


def _create_bound_pod(ctx, cluster_name, endpoint, ca_data_b64, namespace, sa_name):
    """Create a Pod OBJECT purely to get a UID a TokenRequest can bind to. It is deliberately
    unschedulable (a nodeSelector no node will ever satisfy on a cluster with no node group or
    Fargate profile) -- it must exist, never run."""
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    pod_name = ctx.unique_name("sim2real-podid-") + "-" + namespace + "-" + sa_name
    body = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace},
        "spec": {
            "serviceAccountName": sa_name,
            "restartPolicy": "Never",
            "nodeSelector": {"sim2real.invalid/never-schedule": "true"},
            "containers": [{"name": "c", "image": "registry.k8s.io/pause:3.9"}],
        },
    }
    path = f"/api/v1/namespaces/{namespace}/pods"
    resp = _k8s_call(ctx, endpoint, ca_data_b64, bearer, "POST", path, body=body)
    ctx.on_cleanup(lambda: _delete_pod_if_present(ctx, cluster_name, endpoint, ca_data_b64, namespace, pod_name))
    return pod_name, resp["metadata"]["uid"]


def _delete_pod_if_present(ctx, cluster_name, endpoint, ca_data_b64, namespace, pod_name):
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    try:
        _k8s_api_request(ctx, endpoint, ca_data_b64, bearer, "DELETE", f"/api/v1/namespaces/{namespace}/pods/{pod_name}")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise


def _bound_service_account_token(
    ctx,
    cluster_name,
    endpoint,
    ca_data_b64,
    namespace,
    sa_name,
    pod_name,
    pod_uid,
    audiences=("pods.eks.amazonaws.com",),
    expiration_seconds=600,
):
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
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
    resp = _k8s_call(ctx, endpoint, ca_data_b64, bearer, "POST", path, body=body)
    return resp["status"]["token"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

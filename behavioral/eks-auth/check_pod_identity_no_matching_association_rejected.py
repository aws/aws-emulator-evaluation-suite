"""pod-identity-no-matching-association-rejected."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-no-matching-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks-auth"]


def _assumed_role_arn_prefix(role_arn):
    """An assumed-role identity is returned under the "sts" service, never "iam" --
    arn:aws:iam::ACCOUNT:role/NAME assumes to arn:aws:sts::ACCOUNT:assumed-role/NAME/<session>."""
    _arn, partition, _service, region, account, resource = role_arn.split(":", 5)
    role_name = resource.split("/", 1)[1]
    return f"arn:{partition}:sts:{region}:{account}:assumed-role/{role_name}"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A valid service account token for a namespace/serviceAccount with no Pod Identity association
    is rejected with ResourceNotFoundException, while the associated identity on the same cluster
    succeeds, so the rejection is about the missing association."""
    cluster_name, endpoint, ca_data = _create_eks_cluster(ctx)
    role_arn, association = _create_pod_identity_association(ctx, cluster_name, "default", "default")
    eks_auth = ctx.client("eks-auth")

    # Positive control: the associated identity succeeds.
    good_token = _get_service_account_token(ctx, cluster_name, endpoint, ca_data, "default", "default")

    def _assume_good():
        return eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=good_token)

    # AccessDeniedException here is IAM trust-policy propagation lag for the just-created pod
    # role, not a real denial -- the association itself already retries InvalidRequestException
    # for the same reason. Both settle well inside this bound on real AWS.
    good_resp = _retry_client_error(
        _assume_good, retry_codes=("InvalidRequestException", "AccessDeniedException"), attempts=12, delay=5
    )
    good_arn = good_resp["assumedRoleUser"]["arn"]
    expected_prefix = _assumed_role_arn_prefix(role_arn)
    assert good_arn.startswith(expected_prefix), f"EXPECTED_PREFIX={expected_prefix!r} GOT={good_arn!r}"

    # Negative: "kube-system"/"default" exists in every cluster (every namespace gets a
    # "default" ServiceAccount automatically) but has no association configured.
    bad_token = _get_service_account_token(ctx, cluster_name, endpoint, ca_data, "kube-system", "default")
    code, message = _client_error(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=bad_token)
    )
    assert code == "ResourceNotFoundException", f"GOT={code!r}"
    assert message == _NO_ASSOCIATION_MESSAGE, f"EXPECTED_MESSAGE={_NO_ASSOCIATION_MESSAGE!r} GOT={message!r}"

    # Effect absent: no association exists for the unassociated identity, and a repeat
    # attempt with the same unassociated token is still consistently rejected (not flaky).
    eks = ctx.client("eks")
    other_assocs = eks.list_pod_identity_associations(clusterName=cluster_name, namespace="kube-system")[
        "associations"
    ]
    assert not any(a["serviceAccount"] == "default" for a in other_assocs), f"GOT={other_assocs!r}"
    code2, message2 = _client_error(
        lambda: eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=bad_token)
    )
    assert code2 == "ResourceNotFoundException", f"GOT={code2!r}"
    assert message2 == _NO_ASSOCIATION_MESSAGE, f"EXPECTED_MESSAGE={_NO_ASSOCIATION_MESSAGE!r} GOT={message2!r}"

    # Restore: create the missing association and prove the SAME (previously rejected) token now
    # succeeds -- closing the loop that the rejection is specifically about the missing
    # association, not something else about the "kube-system" namespace or the token itself.
    # The K8s ServiceAccount token is independent of eks-auth's association state, so bad_token
    # (issued with a 600s expiry, well before it is used here) remains a valid credential to replay.
    restore_role_arn, _restore_association = _create_pod_identity_association(ctx, cluster_name, "kube-system", "default")

    def _assume_restored():
        return eks_auth.assume_role_for_pod_identity(clusterName=cluster_name, token=bad_token)

    restored_resp = _retry_client_error(
        _assume_restored, retry_codes=("InvalidRequestException", "AccessDeniedException"), attempts=12, delay=5
    )
    restored_arn = restored_resp["assumedRoleUser"]["arn"]
    restored_expected_prefix = _assumed_role_arn_prefix(restore_role_arn)
    assert restored_arn.startswith(restored_expected_prefix), (
        f"EXPECTED_PREFIX={restored_expected_prefix!r} GOT={restored_arn!r}"
    )


# ===== shared helpers =====
_NO_ASSOCIATION_MESSAGE = "The token included in the request has no service account role association for it."


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
    over-permissive target ACCEPTING a call real AWS refuses is the strongest signal
    available and must not be reduced to an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call SUCCEEDED and returned {result!r}")


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


def _vpc_subnets(ctx):
    """Adopt the default VPC if it spans >=2 AZs; otherwise create a dedicated one. A freshly
    provisioned account may have no default VPC at all, so the check must not depend on one."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())
        if len(subnet_ids) >= 2:
            return subnet_ids[:3]

    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eksa-vpc-")}])
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(
            Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eksa-subnet-")}]
        )
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


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
    subnet_ids = _vpc_subnets(ctx)
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
            tags={"sim2real": "audit"},
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


def _k8s_api_request(endpoint, ca_data_b64, bearer_token, method, path, body=None, settle_timeout_s=90):
    """A cluster that just reached ACTIVE can still have a DNS-unresolvable API endpoint for a
    short window (real AWS: `Name or service not known`) -- that is endpoint settle lag, not a
    request failure, so it is retried; an HTTP-level response (even an error one) is not."""
    ca_pem = base64.b64decode(ca_data_b64).decode("utf-8")
    ssl_ctx = ssl.create_default_context(cadata=ca_pem)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(endpoint.rstrip("/") + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {bearer_token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    deadline = time.time() + settle_timeout_s
    while True:
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError:
            if time.time() >= deadline:
                raise
            time.sleep(5)


def _ensure_bound_pod(ctx, cluster_name, endpoint, ca_data_b64, namespace, sa_name):
    """EKS Pod Identity requires the SA token's `kubernetes.io/pod` claim (real AWS:
    InvalidTokenException "missing required claim - kubernetes.io/pod" without it), which the
    TokenRequest API only sets when the request is bound to a real Pod object. No node/kubelet is
    needed for the object to exist and carry a UID -- it can stay Pending forever."""
    admin_bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    pod_name = ctx.unique_name("sim2real-eksa-pod-").lower()
    pod_body = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name},
        "spec": {
            "serviceAccountName": sa_name,
            "containers": [{"name": "main", "image": "registry.k8s.io/pause:3.9"}],
        },
    }
    created = _k8s_api_request(
        endpoint, ca_data_b64, admin_bearer, "POST", f"/api/v1/namespaces/{namespace}/pods", body=pod_body
    )
    pod_uid = created["metadata"]["uid"]
    ctx.on_cleanup(
        lambda: _k8s_api_request(
            endpoint,
            ca_data_b64,
            _eks_k8s_bearer_token(ctx, cluster_name),
            "DELETE",
            f"/api/v1/namespaces/{namespace}/pods/{pod_name}",
        )
    )
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
    pod_name, pod_uid = _ensure_bound_pod(ctx, cluster_name, endpoint, ca_data_b64, namespace, sa_name)
    bearer = _eks_k8s_bearer_token(ctx, cluster_name)
    body = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "audiences": list(audiences),
            "expirationSeconds": expiration_seconds,
            "boundObjectRef": {"apiVersion": "v1", "kind": "Pod", "name": pod_name, "uid": pod_uid},
        },
    }
    path = f"/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token"
    resp = _k8s_api_request(endpoint, ca_data_b64, bearer, "POST", path, body=body)
    return resp["status"]["token"]


# EC2 network teardown: an EKS cluster's ENIs leave the VPC asynchronously, and until then
# DeleteSubnet / DeleteVpc fail with DependencyViolation. Wait for them, retry that code inside one
# window shared by the check's network deletes (it follows the cluster delete within the cleanup
# budget), then raise naming the ENIs still attached; every other error propagates.
_NET_TEARDOWN_S = 150.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""eks-fargate-execution-role-pulls-ecr-image."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-fargate-execution-role-pulls-ecr-image"
GROUP = "image-pull"
SERVICES = ["ecr", "eks", "logs"]
_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """A pod on an EKS Fargate profile, with no node group and no imagePullSecrets, pulls its
    private ECR image: the pull can only succeed through the profile's pod execution role
    carrying AmazonEKSFargatePodExecutionRolePolicy."""
    import kubernetes  # noqa: F401 - a runner without it raises ImportError, not a finding

    ec2 = ctx.client("ec2")
    eks = ctx.client("eks")
    ecr = ctx.client("ecr")

    private_subnet_ids = _create_private_networking(ctx, ec2)

    _, cluster_role_arn = _create_role(
        ctx,
        "sim2real-eksf-clrole-",
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "eks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
        managed_policy_arns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    _, pod_exec_role_arn = _create_role(
        ctx,
        "sim2real-eksf-podexec-",
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "eks-fargate-pods.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
        ],
    )

    repo_name = ctx.unique_name("sim2real-fargate-pull-")
    repo = ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    tag = "sim2real-test"
    _push_scratch_image(ecr, repo_name, tag)
    image_uri = f"{repo['repositoryUri']}:{tag}"

    cluster_name = ctx.unique_name("sim2real-eksf-")
    _retry_role_not_yet_assumable(
        lambda: eks.create_cluster(
            name=cluster_name,
            roleArn=cluster_role_arn,
            resourcesVpcConfig={"subnetIds": private_subnet_ids},
            tags=dict(_TAGS),
        )
    )
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    cluster = _wait_cluster_active(eks, cluster_name)

    profile_name = ctx.unique_name("sim2real-fp-")
    _retry_role_not_yet_assumable(
        lambda: eks.create_fargate_profile(
            fargateProfileName=profile_name,
            clusterName=cluster_name,
            podExecutionRoleArn=pod_exec_role_arn,
            subnets=private_subnet_ids,
            selectors=[{"namespace": "default"}],
            tags=dict(_TAGS),
        )
    )
    ctx.on_cleanup(lambda: _delete_fargate_profile(eks, cluster_name, profile_name))
    _wait_fargate_profile_active(eks, cluster_name, profile_name)

    pod_name = ctx.unique_name("sim2real-pod-")
    _create_pod(ctx, cluster, cluster_name, "default", pod_name, image_uri)
    ctx.on_cleanup(lambda: _delete_pod(ctx, cluster, cluster_name, "default", pod_name))

    pulled = _wait_for_pulled_event(
        ctx, cluster, cluster_name, "default", pod_name, timeout_s=900.0
    )
    assert pulled, (
        f"fargate pod {pod_name} never showed a 'Pulled' event for image {image_uri}"
    )


# ===== helpers =====


def _create_role(ctx, name_prefix, trust_statements, managed_policy_arns=()):
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)
    trust = {"Version": "2012-10-17", "Statement": trust_statements}
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    for pol in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=pol)

    def _cleanup():
        for pol in managed_policy_arns:
            _teardown(lambda pol=pol: iam.detach_role_policy(RoleName=name, PolicyArn=pol), ("NoSuchEntity",))
        _teardown(lambda: iam.delete_role(RoleName=name), ("NoSuchEntity",))

    ctx.on_cleanup(_cleanup)
    return name, role_arn


def _retry_role_not_yet_assumable(fn, timeout_s=90.0):
    """A just-created IAM role is eventually consistent: EKS may not be able to assume it for a
    few seconds after `CreateRole` returns. Retry only that specific window, not any other
    ClientError, so an unrelated rejection (e.g. a real validation failure) still surfaces at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            msg = str(e)
            if "role" not in msg.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_private_networking(ctx, ec2):
    """Build a minimal VPC with 2 private (NAT-routed) subnets — required by Fargate profiles."""
    _tag_spec = [{"Key": k, "Value": v} for k, v in _TAGS.items()]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tag_spec}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _detach_delete_igw():
        _teardown(
            lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id),
            ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"),
        )
        _teardown(
            lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id),
            ("InvalidInternetGatewayID.NotFound",),
        )

    ctx.on_cleanup(_detach_delete_igw)

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones()["AvailabilityZones"][:2]
    ]

    public_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.42.0.0/24",
        AvailabilityZone=azs[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tag_spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))

    private_subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tag_spec}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        private_subnet_ids.append(sid)

    eip_alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": _tag_spec}],
    )["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=eip_alloc))

    nat_gw_id = ec2.create_nat_gateway(
        SubnetId=public_subnet_id,
        AllocationId=eip_alloc,
        TagSpecifications=[{"ResourceType": "natgateway", "Tags": _tag_spec}],
    )["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway(ec2, nat_gw_id))
    ec2.get_waiter("nat_gateway_available").wait(NatGatewayIds=[nat_gw_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    public_rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tag_spec}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    ec2.create_route(
        RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    assoc_pub = ec2.associate_route_table(
        RouteTableId=public_rt_id, SubnetId=public_subnet_id
    )["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_pub))

    private_rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tag_spec}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    ec2.create_route(
        RouteTableId=private_rt_id,
        DestinationCidrBlock="0.0.0.0/0",
        NatGatewayId=nat_gw_id,
    )
    for sid in private_subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=private_rt_id, SubnetId=sid)[
            "AssociationId"
        ]
        ctx.on_cleanup(
            lambda assoc_id=assoc_id: ec2.disassociate_route_table(
                AssociationId=assoc_id
            )
        )

    return private_subnet_ids


def _delete_nat_gateway(ec2, nat_gw_id):
    _teardown(
        lambda: ec2.delete_nat_gateway(NatGatewayId=nat_gw_id),
        ("NatGatewayNotFound", "InvalidNatGatewayID.NotFound"),
        status=lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])["NatGateways"][0]["State"],
        done=("deleted", "failed"),
        what=f"NAT gateway {nat_gw_id}",
        timeout_s=300.0,
    )


def _teardown(delete, gone_codes, *, busy_codes=(), status=None, done=(), what="", timeout_s=90.0):
    """Run one teardown delete: return on its not-found codes, retry busy_codes (a dependency still
    being released) every 2 s, raise the rest; with status, poll it every 2 s until a done state or
    a not-found code. Raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    if status is None:
        return
    while time.monotonic() < deadline:
        try:
            if status() in done:
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone_codes:
                return
            raise
        time.sleep(2)
    raise AssertionError(f"{what} still not deleted {timeout_s:.0f}s after its delete")


def _build_scratch_image_blobs():
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    uncompressed = tar_buf.getvalue()
    diff_id = "sha256:" + hashlib.sha256(uncompressed).hexdigest()
    compressed = gzip.compress(uncompressed)
    layer_digest = "sha256:" + hashlib.sha256(compressed).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Cmd": ["/bin/true"]},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": "2024-01-01T00:00:00Z"}],
    }
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    return compressed, layer_digest, config_bytes, config_digest


def _upload_blob(ecr, repo_name, blob, digest):
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )


def _push_scratch_image(ecr, repo_name, tag):
    compressed, layer_digest, config_bytes, config_digest = _build_scratch_image_blobs()
    _upload_blob(ecr, repo_name, compressed, layer_digest)
    _upload_blob(ecr, repo_name, config_bytes, config_digest)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(compressed),
                "digest": layer_digest,
            }
        ],
    }
    ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
        imageManifestMediaType=manifest["mediaType"],
    )


def _wait_cluster_active(eks, name, timeout_s=1500.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _wait_fargate_profile_active(eks, cluster_name, profile_name, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_fargate_profile(
            clusterName=cluster_name, fargateProfileName=profile_name
        )["fargateProfile"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "CREATE_FAILED":
            raise AssertionError(
                f"fargate profile {profile_name} entered CREATE_FAILED"
            )
        time.sleep(2)
    raise AssertionError(
        f"fargate profile {profile_name} did not become ACTIVE within {timeout_s}s"
    )


def _delete_fargate_profile(eks, cluster_name, profile_name):
    _teardown(
        lambda: eks.delete_fargate_profile(clusterName=cluster_name, fargateProfileName=profile_name),
        ("ResourceNotFoundException",),
        status=lambda: eks.describe_fargate_profile(
            clusterName=cluster_name, fargateProfileName=profile_name
        )["fargateProfile"]["status"],
        what=f"fargate profile {profile_name}",
        timeout_s=600.0,
    )


def _delete_cluster(eks, cluster_name):
    _teardown(
        lambda: eks.delete_cluster(name=cluster_name),
        ("ResourceNotFoundException",),
        busy_codes=("ResourceInUseException",),
        status=lambda: eks.describe_cluster(name=cluster_name)["cluster"]["status"],
        what=f"cluster {cluster_name}",
        timeout_s=600.0,
    )


def _eks_bearer_token(ctx, cluster_name):
    """Build a k8s-aws-v1 bearer token exactly as `aws eks get-token` does: a presigned (but
    never sent) GetCallerIdentity request, base64url-encoded. Signed through `ctx.client("sts")`
    so the token is signed with the same credentials ctx uses for every other call in this check,
    never the ambient credential chain."""
    sts = ctx.client("sts")
    signer = sts._request_signer
    params = {
        "method": "GET",
        "url": ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com") + "/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed_url = signer.generate_presigned_url(
        params,
        region_name=ctx.region,
        expires_in=60,
        operation_name="GetCallerIdentity",
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode(
        "utf-8"
    ).rstrip("=")


def _k8s_core_v1(ctx, cluster, cluster_name):
    from kubernetes import client as k8s_client

    ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    ca_file.write(base64.b64decode(cluster["certificateAuthority"]["data"]))
    # The cluster's API server is a host the target published: reach it through ctx. Its
    # certificate is signed by the cluster's own CA, so that CA stays pinned; a trust bundle the
    # run gives in ctx.http_verify (an emulator's) is trusted beside it, and False turns
    # verification off as it does for every other call to the target.
    if isinstance(ctx.http_verify, str):
        with open(ctx.http_verify, "rb") as bundle:
            ca_file.write(b"\n" + bundle.read())
    ca_file.close()
    host, route = ctx.endpoint_route(cluster["endpoint"])
    configuration = k8s_client.Configuration()
    configuration.host = host
    configuration.ssl_ca_cert = ca_file.name
    configuration.verify_ssl = ctx.http_verify is not False
    configuration.api_key = {
        "authorization": "Bearer " + _eks_bearer_token(ctx, cluster_name)
    }
    api_client = k8s_client.ApiClient(configuration)
    for name, value in route.items():
        api_client.set_default_header(name, value)
    return k8s_client.CoreV1Api(api_client)


def _create_pod(
    ctx, cluster, cluster_name, namespace, pod_name, image_uri, service_account=None
):
    core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
    spec: dict[str, Any] = {
        "restartPolicy": "Never",
        "containers": [{"name": "test", "image": image_uri, "command": ["/bin/true"]}],
    }
    if service_account:
        spec["serviceAccountName"] = service_account
    body = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace},
        "spec": spec,
    }
    core_v1.create_namespaced_pod(namespace, body)


def _delete_pod(ctx, cluster, cluster_name, namespace, pod_name):
    from kubernetes.client.exceptions import ApiException

    core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
    try:
        core_v1.delete_namespaced_pod(pod_name, namespace, grace_period_seconds=0)
    except ApiException as exc:
        if exc.status != 404:
            raise


def _wait_for_pulled_event(
    ctx, cluster, cluster_name, namespace, pod_name, timeout_s=900.0
):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
        events = core_v1.list_namespaced_event(
            namespace, field_selector=f"involvedObject.name={pod_name}"
        )
        for e in events.items:
            if e.reason == "Pulled" and "Successfully pulled image" in (
                e.message or ""
            ):
                return True
        time.sleep(2)
    return False


# Network deletes wait (bounded) for the ENIs of asynchronously deleted resources (load balancers,
# tasks, clusters) to leave, retrying DependencyViolation in one window shared by all of a check's
# network deletes and sized to the cleanup budget; then they raise, naming the ENIs still attached.
_NET_TEARDOWN_S = 1260.0
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
        _time.sleep(10)
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
        _time.sleep(10)


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

"""eks-nodegroup-pulls-private-ecr-image."""

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

CHECK = "eks-nodegroup-pulls-private-ecr-image"
GROUP = "image-pull"
SERVICES = ["ecr", "eks", "logs"]

_MANAGED_TAG_KEY = "sim2real:managed"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """A pod on an EKS managed node group whose node role has AmazonEC2ContainerRegistryReadOnly
    pulls a private ECR image with no imagePullSecrets: the kubelet reports a successful pull."""
    import kubernetes  # noqa: F401 - a runner without it raises ImportError, not a finding

    ec2 = ctx.client("ec2")
    ctx.client("iam")
    eks = ctx.client("eks")
    ecr = ctx.client("ecr")

    vpc_id, subnet_ids = _default_vpc_subnets(ctx, ec2)

    _, cluster_role_arn = _create_role(
        ctx,
        "sim2real-eks-clrole-",
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "eks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
        managed_policy_arns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    _, node_role_arn = _create_role(
        ctx,
        "sim2real-eks-noderole-",
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        ],
    )

    repo_name = ctx.unique_name("sim2real-nodegroup-pull-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    tag = "sim2real-test"
    _push_scratch_image(ecr, repo_name, tag)
    image_uri = f"{repo['repositoryUri']}:{tag}"

    cluster_name = ctx.unique_name("sim2real-eks-")
    _create_cluster_with_role_propagation_retry(
        ctx, eks, cluster_name, cluster_role_arn, subnet_ids
    )
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    cluster = _wait_cluster_active(eks, cluster_name)

    ng_name = ctx.unique_name("sim2real-ng-")
    _create_nodegroup_with_role_propagation_retry(
        ctx, eks, cluster_name, ng_name, subnet_ids, node_role_arn
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(eks, cluster_name, ng_name))
    _wait_nodegroup_active(eks, cluster_name, ng_name)

    pod_name = ctx.unique_name("sim2real-pod-")
    _create_pod(ctx, cluster, cluster_name, "default", pod_name, image_uri)
    ctx.on_cleanup(lambda: _delete_pod(ctx, cluster, cluster_name, "default", pod_name))

    pulled = _wait_for_pulled_event(
        ctx, cluster, cluster_name, "default", pod_name, timeout_s=600.0
    )
    assert pulled, f"pod {pod_name} never showed a 'Pulled' event for image {image_uri}"


# ===== helpers =====


def _create_role(ctx, name_prefix, trust_statements, managed_policy_arns=()):
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)
    trust = {"Version": "2012-10-17", "Statement": trust_statements}
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
    )["Role"]["Arn"]
    for pol in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=pol)

    def _cleanup():
        for pol in managed_policy_arns:
            _teardown(lambda pol=pol: iam.detach_role_policy(RoleName=name, PolicyArn=pol), ("NoSuchEntity",))
        _teardown(lambda: iam.delete_role(RoleName=name), ("NoSuchEntity",))

    ctx.on_cleanup(_cleanup)
    # IAM propagation lag is absorbed where the role must be visible (create_cluster,
    # create_nodegroup), by retrying the error EKS raises until the role has propagated.
    return name, role_arn


def _retry_role_propagation(ctx, fn, window_s=80.0):
    """Call fn, retrying every 2 s to a deadline on the InvalidParameterException EKS raises while
    it cannot yet see a just-created IAM role (propagation lag)."""
    left = ctx.time_left()
    deadline = time.monotonic() + (window_s if left is None else min(window_s, left))
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_cluster_with_role_propagation_retry(ctx, eks, cluster_name, role_arn, subnet_ids):
    """create_cluster, retried while EKS cannot yet see the just-created cluster role."""
    _retry_role_propagation(
        ctx,
        lambda: eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids},
            tags={_MANAGED_TAG_KEY: "true"},
        ),
    )


def _create_nodegroup_with_role_propagation_retry(
    ctx, eks, cluster_name, ng_name, subnet_ids, node_role_arn
):
    """create_nodegroup, retried while EKS cannot yet see the just-created node role."""
    _retry_role_propagation(
        ctx,
        lambda: eks.create_nodegroup(
            clusterName=cluster_name,
            nodegroupName=ng_name,
            subnets=subnet_ids,
            nodeRole=node_role_arn,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            instanceTypes=["t3.medium"],
            # AL2_x86_64 is valid only through Kubernetes 1.32 and the cluster takes the current
            # default version, so the node group uses its successor AMI family.
            amiType="AL2023_x86_64_STANDARD",
            tags={_MANAGED_TAG_KEY: "true"},
        ),
    )


def _default_vpc_subnets(ctx, ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to host the EKS cluster's subnets"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError(
            "shared network VPC does not have subnets in >=2 availability zones required by EKS"
        )
    return vpc_id, subnet_ids[:3]


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


def _wait_nodegroup_active(eks, cluster_name, ng_name, timeout_s=900.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)[
            "nodegroup"
        ]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] in ("CREATE_FAILED", "DEGRADED"):
            raise AssertionError(f"nodegroup {ng_name} entered {desc['status']}")
        time.sleep(2)
    raise AssertionError(
        f"nodegroup {ng_name} did not become ACTIVE within {timeout_s}s"
    )


def _delete_nodegroup(eks, cluster_name, ng_name):
    _teardown(
        lambda: eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=ng_name),
        ("ResourceNotFoundException",),
        status=lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)[
            "nodegroup"
        ]["status"],
        what=f"nodegroup {ng_name}",
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


def _eks_bearer_token(ctx, cluster_name):
    from botocore.signers import RequestSigner

    # Sign with the identity ctx.client() uses: a fresh botocore session would resolve the
    # ambient credential chain and authenticate the pod-scheduling half as another principal.
    sts = ctx.client("sts")
    signer = RequestSigner(
        sts.meta.service_model.service_id,
        ctx.region,
        "sts",
        "v4",
        sts._request_signer._credentials,
        sts.meta.events,
    )
    params = {
        "method": "GET",
        "url": ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com") + "/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed_url = signer.generate_presigned_url(
        params, region_name=ctx.region, expires_in=60, operation_name=""
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
    ctx, cluster, cluster_name, namespace, pod_name, timeout_s=600.0
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

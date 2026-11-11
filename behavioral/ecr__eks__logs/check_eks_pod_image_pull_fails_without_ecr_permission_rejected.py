"""eks-pod-image-pull-fails-without-ecr-permission-rejected."""

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

CHECK = "eks-pod-image-pull-fails-without-ecr-permission-rejected"
GROUP = "image-pull"
SERVICES = ["ecr", "eks", "logs"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """A node role with ecr:GetAuthorizationToken but not BatchGetImage/GetDownloadUrlForLayer
    leaves a private-image pod in ImagePullBackOff while a public-image pod on the same node pulls;
    granting the two permissions lets the recreated private pod pull."""
    import kubernetes  # noqa: F401 - a runner without it raises ImportError, not a finding

    ec2 = ctx.client("ec2")
    eks = ctx.client("eks")
    ecr = ctx.client("ecr")

    vpc_id, subnet_ids = _default_vpc_subnets(ctx, ec2)

    _, cluster_role_arn = _create_role(
        ctx,
        "sim2real-eksneg-clrole-",
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "eks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
        managed_policy_arns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    # The node can pull from repositories in OTHER accounts only: a node also needs the VPC CNI
    # and kube-proxy images from EKS's own registry account to become Ready (without them the
    # node group stays CREATING), but nothing in this account, so the check's private image
    # stays unpullable.
    own_account = ctx.client("sts").get_caller_identity()["Account"]
    restricted_ecr_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:ResourceAccount": own_account}},
            },
        ],
    }
    node_role_name, node_role_arn = _create_role(
        ctx,
        "sim2real-eksneg-noderole-",
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
        ],
        inline_policy_document=restricted_ecr_policy,
    )

    repo_name = ctx.unique_name("sim2real-noperm-pull-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "Name", "Value": repo_name}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    tag = "sim2real-test"
    _push_scratch_image(ecr, repo_name, tag)
    private_image_uri = f"{repo['repositoryUri']}:{tag}"
    public_image_uri = "public.ecr.aws/docker/library/hello-world:linux"

    cluster_name = ctx.unique_name("sim2real-eksneg-")
    _create_with_role_propagation_retry(
        lambda: eks.create_cluster(
            name=cluster_name,
            roleArn=cluster_role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids},
            tags={"Name": cluster_name},
        )
    )
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    cluster = _wait_cluster_active(eks, cluster_name)

    ng_name = ctx.unique_name("sim2real-ngneg-")
    _create_with_role_propagation_retry(
        lambda: eks.create_nodegroup(
            clusterName=cluster_name,
            nodegroupName=ng_name,
            subnets=subnet_ids,
            nodeRole=node_role_arn,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            instanceTypes=["t3.medium"],
            # AL2_x86_64 is retired for current control-plane versions: CreateNodegroup answers
            # "AMI Type AL2_x86_64 is only supported for kubernetes versions 1.32 or earlier".
            # AL2023 is what the eks suite's own nodegroup checks use.
            amiType="AL2023_x86_64_STANDARD",
            tags={"Name": ng_name},
        )
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(eks, cluster_name, ng_name))
    _wait_nodegroup_active(eks, cluster_name, ng_name)

    private_pod = ctx.unique_name("sim2real-priv-")
    _create_pod(ctx, cluster, cluster_name, "default", private_pod, private_image_uri)
    ctx.on_cleanup(
        lambda: _delete_pod(ctx, cluster, cluster_name, "default", private_pod)
    )

    control_pod = ctx.unique_name("sim2real-ctrl-")
    _create_pod(ctx, cluster, cluster_name, "default", control_pod, public_image_uri)
    ctx.on_cleanup(
        lambda: _delete_pod(ctx, cluster, cluster_name, "default", control_pod)
    )

    # Positive control: the same node, without any ECR-specific permission, must still pull a
    # public image fine -- proving the node/cluster is healthy in general.
    control_pulled = _wait_for_pulled_event(
        ctx, cluster, cluster_name, "default", control_pod, timeout_s=600.0
    )
    assert control_pulled, (
        f"control pod {control_pod} (public image) never pulled -- cluster itself is unhealthy"
    )

    # Negative: the private-repo pod must land in ImagePullBackOff and must never have pulled.
    backoff = _wait_for_image_pull_backoff(
        ctx, cluster, cluster_name, "default", private_pod, timeout_s=600.0
    )
    assert backoff, f"private-image pod {private_pod} never reached ImagePullBackOff"

    ever_pulled = _wait_for_pulled_event(
        ctx, cluster, cluster_name, "default", private_pod, timeout_s=1.0
    )
    assert not ever_pulled, (
        f"private-image pod {private_pod} recorded a Pulled event despite missing permission"
    )

    # Restore: grant exactly the two permissions that were withheld to the SAME node role, then
    # recreate the SAME private-image pod. This is what separates "blocked by the missing
    # permission" from "this node/image combination can never pull" -- a target that fakes
    # ImagePullBackOff unconditionally passes every assertion above but fails this one.
    restore_policy_name = "ecr-read-restore"
    iam = ctx.client("iam")
    restore_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=node_role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps(restore_policy),
    )
    ctx.on_cleanup(
        lambda: _delete_role_policy(iam, node_role_name, restore_policy_name)
    )

    _delete_pod(ctx, cluster, cluster_name, "default", private_pod)
    _wait_for_pod_gone(
        ctx, cluster, cluster_name, "default", private_pod, timeout_s=120.0
    )
    _create_pod(ctx, cluster, cluster_name, "default", private_pod, private_image_uri)

    restored_pulled = _wait_for_pulled_event(
        ctx, cluster, cluster_name, "default", private_pod, timeout_s=600.0
    )
    assert restored_pulled, (
        f"private-image pod {private_pod} still never recorded a Pulled event after granting "
        f"ecr:BatchGetImage/ecr:GetDownloadUrlForLayer to the node role -- the earlier "
        f"ImagePullBackOff was not actually caused by the missing permission"
    )


# ===== helpers =====


def _create_role(
    ctx,
    name_prefix,
    trust_statements,
    managed_policy_arns=(),
    inline_policy_document=None,
):
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)
    trust = {"Version": "2012-10-17", "Statement": trust_statements}
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": name}],
    )["Role"]["Arn"]
    for pol in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=pol)
    if inline_policy_document is not None:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy_document),
        )

    def _cleanup():
        for pol in managed_policy_arns:
            _ignore_no_such_entity(lambda pol=pol: iam.detach_role_policy(RoleName=name, PolicyArn=pol))
        if inline_policy_document is not None:
            _delete_role_policy(iam, name, "inline")
        _ignore_no_such_entity(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_cleanup)
    return name, role_arn


def _ignore_no_such_entity(fn):
    """Run one IAM teardown call: an already-absent entity is fine, every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_policy(iam, role_name, policy_name):
    _ignore_no_such_entity(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_with_role_propagation_retry(fn, timeout_s=120.0):
    """A just-created IAM role can take up to ~30-60s to propagate to other services' policy
    caches; retry the dependent call on that SPECIFIC transient rather than guessing a fixed
    pre-sleep that either under- or over-waits."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            error = e.response.get("Error", {})
            transient = error.get("Code") in (
                "InvalidParameterException",
                "AccessDeniedException",
            ) and ("role" in error.get("Message", "").lower())
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)


#: Zones EKS does not offer control-plane placement in, by zone ID (names differ per account).
_EKS_UNSUPPORTED_AZ_IDS = {"use1-az3", "usw2-az4", "cac1-az3"}


def _default_vpc_subnets(ctx, ec2):
    """The run's shared network and up to three of its subnets in EKS-supported zones."""
    network = ctx.network()
    zone_ids = {
        z["ZoneName"]: z["ZoneId"]
        for z in ec2.describe_availability_zones(
            ZoneNames=sorted(network.subnets))["AvailabilityZones"]
    }
    subnet_ids = [
        network.subnets[az] for az in sorted(network.subnets)
        if zone_ids.get(az) not in _EKS_UNSUPPORTED_AZ_IDS
    ]
    if len(subnet_ids) < 2:
        raise AssertionError(
            "the shared network does not have subnets in >=2 EKS-supported availability zones"
        )
    return network.vpc_id, subnet_ids[:3]


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


def _wait_nodegroup_active(eks, cluster_name, ng_name, timeout_s=1500.0):
    deadline = time.monotonic() + timeout_s
    desc = {}
    while time.monotonic() < deadline:
        desc = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)[
            "nodegroup"
        ]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] in ("CREATE_FAILED", "DEGRADED"):
            raise AssertionError(
                f"nodegroup {ng_name} entered {desc['status']}: {desc.get('health', {}).get('issues')}"
            )
        time.sleep(2)
    raise AssertionError(
        f"nodegroup {ng_name} did not become ACTIVE within {timeout_s}s "
        f"(status {desc.get('status')!r}, health {desc.get('health', {}).get('issues')})"
    )


def _delete_nodegroup(eks, cluster_name, ng_name, timeout_s=900.0):
    """Delete the node group and wait until it is gone; only an absent one is fine."""
    from botocore.exceptions import ClientError

    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"nodegroup {ng_name} still exists {timeout_s}s after DeleteNodegroup")


def _delete_cluster(eks, cluster_name, timeout_s=900.0):
    """Delete the cluster (retrying while a node group or update still holds it) and wait."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=cluster_name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(20)
    # The wait for the cluster to go gets a window of its own: a delete accepted late in the
    # retry window is not reported as a failure.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError(f"EKS cluster {cluster_name} still exists {timeout_s}s after DeleteCluster")


def _eks_bearer_token(ctx, cluster_name):
    from botocore.signers import RequestSigner

    # Sign with the identity every other ctx.client(...) call in this check uses, not a bare
    # botocore.session.get_session(), which resolves the ambient chain and would authenticate to
    # the cluster's API server as an unmapped principal.
    sts = ctx.client("sts")
    creds = sts._request_signer._credentials
    service_id = sts.meta.service_model.service_id
    signer = RequestSigner(service_id, ctx.region, "sts", "v4", creds, sts.meta.events)
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


def _create_pod(ctx, cluster, cluster_name, namespace, pod_name, image_uri):
    core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
    body: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace},
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {"name": "test", "image": image_uri, "command": ["/bin/true"]}
            ],
        },
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
    while True:
        core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
        events = core_v1.list_namespaced_event(
            namespace, field_selector=f"involvedObject.name={pod_name}"
        )
        for e in events.items:
            if e.reason == "Pulled" and "Successfully pulled image" in (
                e.message or ""
            ):
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(2)


def _wait_for_pod_gone(
    ctx, cluster, cluster_name, namespace, pod_name, timeout_s=120.0
):
    from kubernetes.client.exceptions import ApiException

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
        try:
            core_v1.read_namespaced_pod(pod_name, namespace)
        except ApiException as e:
            if e.status == 404:
                return
            raise
        time.sleep(5)
    raise AssertionError(f"pod {pod_name} was not deleted within {timeout_s}s")


def _wait_for_image_pull_backoff(
    ctx, cluster, cluster_name, namespace, pod_name, timeout_s=600.0
):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
        pod = core_v1.read_namespaced_pod(pod_name, namespace)
        for cs in pod.status.container_statuses or []:
            waiting = cs.state.waiting
            if waiting and waiting.reason == "ImagePullBackOff":
                return True
        time.sleep(2)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

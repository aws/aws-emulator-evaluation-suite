"""eks-irsa-role-pulls-ecr-image-without-imagepullsecret."""

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

CHECK = "eks-irsa-role-pulls-ecr-image-without-imagepullsecret"
GROUP = "image-pull"
SERVICES = ["ecr", "eks", "logs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """A pod with an IRSA-annotated ServiceAccount pulls a private ECR image with no imagePullSecrets,
    and the ServiceAccount's OIDC token exchanged via AssumeRoleWithWebIdentity can DescribeImages.
    """
    import kubernetes  # noqa: F401 - a runner without it raises ImportError, not a finding

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")

    sts.get_caller_identity()["Account"]
    vpc_id, subnet_ids = _default_vpc_subnets(ctx, ec2)

    _, cluster_role_arn = _create_role(
        ctx,
        "sim2real-irsa-clrole-",
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
        "sim2real-irsa-noderole-",
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

    repo_name = ctx.unique_name("sim2real-irsa-repo-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    tag = "sim2real-test"
    _push_scratch_image(ecr, repo_name, tag)
    image_uri = f"{repo['repositoryUri']}:{tag}"

    cluster_name = ctx.unique_name("sim2real-irsa-")
    eks.create_cluster(
        name=cluster_name,
        roleArn=cluster_role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    cluster = _wait_cluster_active(eks, cluster_name, timeout_s=_budget_s(ctx, 1500.0), ctx=ctx)
    oidc_issuer = cluster["identity"]["oidc"][
        "issuer"
    ]  # e.g. https://oidc.eks.<region>.amazonaws.com/id/XXXX
    issuer_host_path = oidc_issuer.replace("https://", "")

    ng_name = ctx.unique_name("sim2real-irsa-ng-")
    eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=ng_name,
        subnets=subnet_ids,
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=["t3.medium"],
        # AL2_x86_64 is only supported for Kubernetes 1.32 or earlier.
        amiType="AL2023_x86_64_STANDARD",
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(eks, cluster_name, ng_name))
    _wait_nodegroup_active(eks, cluster_name, ng_name, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)

    oidc_provider_arn = iam.create_open_id_connect_provider(
        Url=oidc_issuer,
        ClientIDList=["sts.amazonaws.com"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(
        lambda: iam.delete_open_id_connect_provider(
            OpenIDConnectProviderArn=oidc_provider_arn
        )
    )

    namespace = "default"
    sa_name = ctx.unique_name("sim2real-irsa-sa-")
    irsa_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": oidc_provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{issuer_host_path}:sub": f"system:serviceaccount:{namespace}:{sa_name}",
                        f"{issuer_host_path}:aud": "sts.amazonaws.com",
                    }
                },
            }
        ],
    }
    _, irsa_role_arn = _create_role(
        ctx,
        "sim2real-irsa-podrole-",
        irsa_trust["Statement"],
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
        ],
    )

    core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
    core_v1.create_namespaced_service_account(
        namespace,
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": sa_name,
                "namespace": namespace,
                "annotations": {"eks.amazonaws.com/role-arn": irsa_role_arn},
            },
        },
    )
    ctx.on_cleanup(
        lambda: _delete_service_account(ctx, cluster, cluster_name, namespace, sa_name)
    )

    pod_name = ctx.unique_name("sim2real-irsa-pod-")
    _create_pod(
        ctx,
        cluster,
        cluster_name,
        namespace,
        pod_name,
        image_uri,
        service_account=sa_name,
    )
    ctx.on_cleanup(lambda: _delete_pod(ctx, cluster, cluster_name, namespace, pod_name))

    pulled = _wait_for_pulled_event(
        ctx, cluster, cluster_name, namespace, pod_name, timeout_s=_budget_s(ctx, 600.0)
    )
    if not pulled and _budget_spent(ctx):
        raise TimeoutError(
            f"a 'Pulled' event on pod {pod_name}: the run budget ended first; not graded")
    assert pulled, f"pod {pod_name} never showed a 'Pulled' event for image {image_uri}"

    pod = core_v1.read_namespaced_pod(pod_name, namespace)
    assert not pod.spec.image_pull_secrets, (
        "pod unexpectedly carries an imagePullSecrets entry"
    )
    sa = core_v1.read_namespaced_service_account(sa_name, namespace)
    assert not sa.image_pull_secrets, (
        "service account unexpectedly carries an imagePullSecrets entry"
    )

    # The node role, not the ServiceAccount, services the image pull, so the IRSA identity is
    # exercised separately: exchange a projected token as the pod-identity webhook would.
    token = core_v1.create_namespaced_service_account_token(
        sa_name,
        namespace,
        {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {"audiences": ["sts.amazonaws.com"], "expirationSeconds": 600},
        },
    ).status.token

    irsa_sts = ctx.client("sts")
    creds = _assume_role_with_web_identity(
        irsa_sts, irsa_role_arn, token, timeout_s=_budget_s(ctx, 60.0), ctx=ctx
    )

    irsa_ecr = ctx.client(
        "ecr",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    described = irsa_ecr.describe_images(
        repositoryName=repo_name, imageIds=[{"imageTag": tag}]
    )
    assert len(described["imageDetails"]) == 1, (
        "IRSA-assumed credentials could not describe the pushed image"
    )



def _create_role(ctx, name_prefix, trust_statements, managed_policy_arns=()):
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)
    trust = {"Version": "2012-10-17", "Statement": trust_statements}
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    for pol in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=pol)

    def _cleanup():
        calls = [lambda pol=pol: iam.detach_role_policy(RoleName=name, PolicyArn=pol) for pol in managed_policy_arns]
        for call in calls + [lambda: iam.delete_role(RoleName=name)]:
            try:
                call()
            except ClientError as exc:
                if not _not_found(exc):
                    raise

    ctx.on_cleanup(_cleanup)
    _wait_role_policies_attached(iam, name, managed_policy_arns, timeout_s=_budget_s(ctx, 60.0),
                                 ctx=ctx)
    return name, role_arn


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0

def _assume_role_with_web_identity(sts, role_arn, token, timeout_s=60.0, ctx=None):
    """Exchange the token, retrying while IAM has not yet propagated the new OIDC provider or the
    role's trust policy to STS; any other error, or a refusal past the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sts.assume_role_with_web_identity(
                RoleArn=role_arn,
                RoleSessionName="sim2real-irsa-pod",
                WebIdentityToken=token,
            )["Credentials"]
        except Exception as exc:
            err = getattr(exc, "response", {}).get("Error", {})
            message = err.get("Message", "")
            propagating = (
                err.get("Code") == "AccessDenied"
                and "sts:AssumeRoleWithWebIdentity" in message
            ) or (
                err.get("Code") == "InvalidIdentityToken"
                and "No OpenIDConnect provider found" in message
            )
            if not propagating or time.monotonic() >= deadline:
                if propagating and ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(
                        f"STS accepting the web identity for {role_arn}: the run budget ended "
                        f"first; not graded") from exc
                raise
        time.sleep(2)


def _wait_role_policies_attached(iam, name, managed_policy_arns, timeout_s=60.0, ctx=None):
    """Poll until the role lists every attached managed policy (IAM is eventually consistent)."""
    wanted = set(managed_policy_arns)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        attached = {
            p["PolicyArn"]
            for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
        }
        if wanted <= attached:
            return
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"role {name} listing its policies: the run budget ended first; not graded")
    raise AssertionError(
        f"role {name} did not reflect attached policies {wanted!r} within {timeout_s}s"
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


def _wait_cluster_active(eks, name, timeout_s=1500.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _wait_nodegroup_active(eks, cluster_name, ng_name, timeout_s=900.0, ctx=None):
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
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(
            f"nodegroup {ng_name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(
        f"nodegroup {ng_name} did not become ACTIVE within {timeout_s}s"
    )


def _not_found(exc) -> bool:
    """The resource is already gone: its service's own not-found code."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return "NotFound" in code or code == "NoSuchEntity"


def _delete_nodegroup(eks, cluster_name, ng_name):
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
    except Exception as exc:
        if _not_found(exc):
            return
        raise RuntimeError(f"nodegroup {ng_name} was not deleted: {exc!r}") from exc
    last = "still described"
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
        except Exception as exc:
            if _not_found(exc):
                return
            last = exc
        time.sleep(2)
    raise RuntimeError(f"nodegroup {ng_name} was not deleted: {last!r}")


def _delete_cluster(eks, cluster_name):
    try:
        eks.delete_cluster(name=cluster_name)
    except Exception as exc:
        if _not_found(exc):
            return
        raise RuntimeError(f"EKS cluster {cluster_name} was not deleted: {exc!r}") from exc
    last = "still described"
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except Exception as exc:
            if _not_found(exc):
                return
            last = exc
        time.sleep(2)
    raise RuntimeError(f"EKS cluster {cluster_name} was not deleted: {last!r}")


def _eks_bearer_token(ctx, cluster_name):
    from botocore.signers import RequestSigner

    # Sign with ctx's client credentials, never the ambient credential chain.
    sts_client = ctx.client("sts")
    signer = RequestSigner(
        sts_client.meta.service_model.service_id,
        ctx.region,
        "sts",
        "v4",
        sts_client._request_signer._credentials,
        sts_client.meta.events,
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
    # The API server's certificate is signed by the cluster CA, so that CA stays pinned; a
    # ctx.http_verify bundle is trusted beside it, and False turns verification off.
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


def _delete_service_account(ctx, cluster, cluster_name, namespace, sa_name):
    from kubernetes.client.exceptions import ApiException

    core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
    try:
        core_v1.delete_namespaced_service_account(sa_name, namespace)
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

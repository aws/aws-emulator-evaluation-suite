"""create-endpoint-nonexistent-config-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-endpoint-nonexistent-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint referencing a non-existent EndpointConfig is rejected, even though
    ResourceNotFound is not in the operation's declared error list -- the service does not
    silently accept a dangling EndpointConfigName reference and leave a stuck Endpoint behind.
    """
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    image = _push_check_image(ctx)[0]

    # --- setup for the positive control: a real model + endpoint config ---
    model_name = ctx.unique_name("sim2real-model-")
    _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={
                "Image": image
            },
            Tags=_TAGS,
        )
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    config_name = ctx.unique_name("sim2real-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "ServerlessConfig": {"MemorySizeInMB": 1024, "MaxConcurrency": 1},
            }
        ],
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name))

    # --- negative: EndpointConfigName does not exist ---
    bad_endpoint_name = ctx.unique_name("sim2real-ep-bad-")
    missing_config_name = ctx.unique_name("sim2real-epc-missing-")
    code, message = _error(
        lambda: sm.create_endpoint(EndpointName=bad_endpoint_name, EndpointConfigName=missing_config_name)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # the message must name the missing config -- otherwise a generic catch-all rejection
    # (e.g. a stub that rejects every CreateEndpoint) would score the same as a real
    # existence check.
    expected = f'Could not find endpoint configuration "{missing_config_name}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the endpoint was never created (DescribeEndpoint does not declare
    # ResourceNotFound; a nonexistent EndpointName surfaces as ValidationException instead)
    describe_code, describe_message = _error(lambda: sm.describe_endpoint(EndpointName=bad_endpoint_name))
    assert describe_code == "ValidationException", f"expected ValidationException, got {describe_code!r}"
    expected_describe = f'Could not find endpoint "{bad_endpoint_name}".'
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # --- positive control: a real EndpointConfig lets CreateEndpoint succeed ---
    good_endpoint_name = ctx.unique_name("sim2real-ep-good-")
    resp = sm.create_endpoint(EndpointName=good_endpoint_name, EndpointConfigName=config_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_endpoint_when_settled(sm, good_endpoint_name))
    assert resp["EndpointArn"].endswith(f"endpoint/{good_endpoint_name}"), (
        f"expected CreateEndpoint's own EndpointArn to end with 'endpoint/{good_endpoint_name}', "
        f"got {resp['EndpointArn']!r}"
    )

    # terminal read: an independent DescribeEndpoint (not the mutating call's own response)
    # confirms the endpoint the positive control just created is real and visible.
    describe = sm.describe_endpoint(EndpointName=good_endpoint_name)
    assert describe["EndpointArn"] == resp["EndpointArn"], (
        f"expected DescribeEndpoint to report the same EndpointArn CreateEndpoint returned, "
        f"got {describe['EndpointArn']!r} vs {resp['EndpointArn']!r}"
    )
    assert describe["EndpointStatus"] in ("Creating", "InService"), (
        f"expected the endpoint created against a real EndpointConfig to read back as "
        f"Creating/InService via an independent DescribeEndpoint, got {describe['EndpointStatus']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    """IAM trust-policy/permissions propagation is eventually consistent; CreateModel
    synchronously verifies the role can pull the container image, so retry (bounded) rather
    than sleep-and-hope while that propagates."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_TAGS,
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateModel synchronously verifies the role can pull the container image from the
    # check's own private ECR repository, so the role needs ECR read permissions.
    ecr_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn))
    return arn


def _delete_endpoint_when_settled(sm, endpoint_name, timeout_s=900.0, interval_s=2.0):
    """DeleteEndpoint refuses an endpoint that is still Creating/Updating, so wait for a
    settled status (bounded, raising on timeout) and then delete; an endpoint that is
    already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sm.describe_endpoint(EndpointName=endpoint_name)["EndpointStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                return
            raise
        if status not in ("Creating", "Updating", "SystemUpdating", "RollingBack", "Deleting"):
            break
        if status == "Deleting":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"endpoint {endpoint_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)
    sm.delete_endpoint(EndpointName=endpoint_name)


def _push_check_image(ctx, tags=("v1",)) -> list[str]:
    """Push a minimal image to a check-owned ECR repository under each tag; return the image URIs.
    SageMaker resolves the image at create time, so it must exist; no inference is served from it."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-sm-repo-").lower()
    repo_uri = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["repository"]["repositoryUri"]
    ctx.on_cleanup(lambda: _delete_check_repository(ecr, repo_name))
    for tag in tags:
        _push_minimal_image(ecr, repo_name, tag)
    return [f"{repo_uri}:{tag}" for tag in tags]


def _delete_check_repository(ecr, repo_name) -> None:
    """Force-delete the repository; RepositoryNotFoundException means already gone, the rest raises."""
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal empty-layer Docker v2 image via the ECR API, without a Docker daemon."""
    import gzip
    import hashlib
    import io
    import tarfile

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    diff_id = hashlib.sha256(tar_bytes).hexdigest()

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    layer_bytes = gz_buf.getvalue()
    layer_digest = hashlib.sha256(layer_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
    }
    config_bytes = json.dumps(config).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()

    def _upload_blob(blob: bytes, digest: str) -> None:
        upload = ecr.initiate_layer_upload(repositoryName=repo_name)
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload["uploadId"],
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name,
                uploadId=upload["uploadId"],
                layerDigests=[f"sha256:{digest}"],
            )
        except ClientError as exc:
            # Identical (e.g. empty) layer content may already exist in the repo.
            if exc.response["Error"]["Code"] != "LayerAlreadyExistsException":
                raise

    _upload_blob(layer_bytes, layer_digest)
    _upload_blob(config_bytes, config_digest)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": f"sha256:{config_digest}",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": f"sha256:{layer_digest}",
            }
        ],
    }
    ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

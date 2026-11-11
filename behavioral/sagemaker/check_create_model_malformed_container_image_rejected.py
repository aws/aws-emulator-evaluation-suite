"""create-model-malformed-container-image-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-malformed-container-image-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel rejects a PrimaryContainer.Image value that is not a well-formed
    registry reference (contains whitespace, which no ECR/registry URI can contain),
    rather than silently accepting it as a usable container image."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    bad_model_name = ctx.unique_name("sim2real-behav-badmodel-")
    malformed_image = "this is not an ecr image uri"  # embedded spaces: not a valid URI

    code, message = _error_code_and_message(
        lambda: sm.create_model(
            ModelName=bad_model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": malformed_image},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{malformed_image}' at 'primaryContainer.image' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: [\\S]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the malformed-image model was never created
    absent_code, absent_message = _error_code_and_message(lambda: sm.describe_model(ModelName=bad_model_name))
    assert absent_code == "ValidationException", f"expected ValidationException, got {absent_code!r}"
    assert absent_message == f'Could not find model "{bad_model_name}".', (
        f"expected message 'Could not find model \"{bad_model_name}\".', got {absent_message!r}"
    )

    # positive control: a syntactically well-formed image reference is accepted. Retried
    # (bounded) rather than slept: a role's trust policy takes a few seconds to propagate to
    # SageMaker after IAM creates it, and only a role-not-yet-trusted error is worth retrying.
    good_model_name = ctx.unique_name("sim2real-behav-goodmodel-")
    good_image = _push_check_image(ctx)[0]
    resp = _retry_until_role_propagates(
        lambda: sm.create_model(
            ModelName=good_model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": good_image},
        )
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=good_model_name))
    assert resp["ModelArn"], f"expected a ModelArn in the response, got {resp!r}"
    desc = sm.describe_model(ModelName=good_model_name)
    assert desc["PrimaryContainer"]["Image"] == good_image, (
        f"expected stored image {good_image!r}, got {desc['PrimaryContainer']['Image']!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_until_role_propagates(fn, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code != "ValidationException" or "role" not in msg.lower():
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"execution role never became usable within {timeout_s}s: {last_err}")


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-smrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateModel synchronously verifies the role can pull the container image, so the role
    # needs real ECR read permissions even for the positive control's publicly-pullable image.
    ecr_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn))
    return arn


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

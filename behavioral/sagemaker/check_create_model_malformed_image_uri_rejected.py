"""create-model-malformed-image-uri-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-malformed-image-uri-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModel with a syntactically malformed container image URI (one containing
    whitespace, which violates the Image field's ^[\\S]+$ pattern) is rejected at the API
    boundary rather than accepted and deferred to deploy time.
    """
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    # --- negative: image URI contains whitespace, violating the pattern constraint ---
    bad_model_name = ctx.unique_name("sim2real-model-bad-")
    code, message = _error_code_and_message(
        lambda: sm.create_model(
            ModelName=bad_model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": "this is not a valid image uri"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'this is not a valid image uri' at "
        "'primaryContainer.image' failed to satisfy constraint: Member must satisfy regular "
        "expression pattern: [\\S]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the model was never created (SageMaker's DescribeModel does not declare
    # ResourceNotFound; a nonexistent ModelName surfaces as ValidationException instead)
    describe_code, describe_message = _error_code_and_message(lambda: sm.describe_model(ModelName=bad_model_name))
    assert describe_code == "ValidationException", f"expected ValidationException, got {describe_code!r}"
    assert describe_message == f'Could not find model "{bad_model_name}".', (
        f"expected message 'Could not find model \"{bad_model_name}\".', got {describe_message!r}"
    )

    # --- positive control: a syntactically valid (non-whitespace) image URI succeeds ---
    # CreateModel checks the caller's iam:PassRole grant for ExecutionRoleArn against a
    # role that may not have finished IAM's own propagation yet, so retry on that specific
    # transient rejection instead of guessing a fixed wait.
    good_model_name = ctx.unique_name("sim2real-model-good-")
    good_image = _push_check_image(ctx)[0]
    deadline = time.monotonic() + 60
    last_code = None
    while True:
        try:
            sm.create_model(
                ModelName=good_model_name,
                ExecutionRoleArn=role_arn,
                PrimaryContainer={"Image": good_image},
                Tags=[{"Key": "sim2real", "Value": "create-model-malformed-image-uri-rejected"}],
            )
            break
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"create_model with a valid image never succeeded within 60s of role "
                    f"creation; last error {last_code!r}"
                ) from e
            time.sleep(3)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=good_model_name))
    desc = sm.describe_model(ModelName=good_model_name)
    assert desc["ModelName"] == good_model_name, f"expected {good_model_name!r}, got {desc.get('ModelName')!r}"


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": "create-model-malformed-image-uri-rejected"}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateModel checks the caller's iam:PassRole grant for ExecutionRoleArn, so the role
    # needs real ECR read permissions (the image itself is a publicly-pullable AWS Deep
    # Learning Container -- its own ECR resource policy grants pull to every account, but the
    # assumed role still needs ecr:GetAuthorizationToken/BatchGetImage on its own side).
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

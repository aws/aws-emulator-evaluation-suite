"""e2e-model-package-group-policy-controls-access-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "e2e-model-package-group-policy-controls-access-lifecycle"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A model package group's resource policy reads back exactly from GetModelPackageGroupPolicy; after
    DeleteModelPackageGroupPolicy the read is refused with ValidationException and its exact message, and
    a second, different policy put afterwards is the one returned.
    """
    sm = ctx.client("sagemaker")
    image = _push_check_image(ctx)[0]
    sts = ctx.client("sts")
    group_name = ctx.unique_name("sim2real-mpg-lifecycle-")

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    account_id = sts.get_caller_identity()["Account"]
    group_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"

    package_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelApprovalStatus="PendingManualApproval",
        InferenceSpecification={
            "Containers": [
                {"Image": image}
            ],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
        # Tags on the versioned model package itself are rejected by real AWS ("Tags are not
        # supported in Model Package versions") -- it inherits the group's tags instead.
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=package_arn))

    def _policy(sid: str) -> dict:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sagemaker:DescribeModelPackageGroup",
                    "Resource": group_arn,
                }
            ],
        }

    first_policy = _policy("FirstGrant")
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(first_policy)
    )
    fetched_first = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert fetched_first == first_policy, f"expected {first_policy}, got {fetched_first}"

    # The model package registered under the group is unaffected by the group's resource
    # policy (that policy only gates cross-account principals, not the owning account).
    batch = sm.batch_describe_model_package(ModelPackageArnList=[package_arn])
    assert package_arn in batch["ModelPackageSummaries"], (
        f"expected {package_arn} in ModelPackageSummaries, got keys "
        f"{list(batch['ModelPackageSummaries'])}"
    )
    fetched_group_name = batch["ModelPackageSummaries"][package_arn]["ModelPackageGroupName"]
    assert fetched_group_name == group_name, f"expected {group_name}, got {fetched_group_name}"

    sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
    revoked_code, revoked_message = _error(
        lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    )
    # GetModelPackageGroupPolicy raises ValidationException (not ResourceNotFound)
    # once the resource policy has been removed.
    assert revoked_code == "ValidationException", (
        f"expected ValidationException after revoke, got {revoked_code}"
    )
    expected = f"Cannot find resource policy for: {group_arn}"
    assert revoked_message == expected, f"expected message {expected!r}, got {revoked_message!r}"

    second_policy = _policy("SecondGrant")
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(second_policy)
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name))
    fetched_second = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert fetched_second == second_policy, f"expected {second_policy}, got {fetched_second}"
    assert fetched_second != first_policy, (
        f"reattached policy must not resurrect the revoked one, got {fetched_second}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a read real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


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
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal empty-layer Docker v2 image via the ECR API, without a Docker daemon."""
    from botocore.exceptions import ClientError
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

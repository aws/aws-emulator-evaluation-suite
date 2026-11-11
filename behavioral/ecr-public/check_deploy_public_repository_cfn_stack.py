"""deploy-public-repository-cfn-stack."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

CHECK = "deploy-public-repository-cfn-stack"
GROUP = "deploy"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation AWS::ECR::PublicRepository stack produces a repository that
    actually accepts a real image push (layer upload + manifest put), not merely
    CREATE_COMPLETE -- confirmed via DescribeImages after the push."""
    repo_name = ctx.unique_name("sim2real-cfn-repo-").lower()
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "PublicRepo": {
                    "Type": "AWS::ECR::PublicRepository",
                    "Properties": {"RepositoryName": repo_name},
                }
            },
            "Outputs": {
                "RepoName": {"Value": {"Ref": "PublicRepo"}},
            },
        }
    )
    _deploy_cfn(ctx, template)

    ecr = _regional_client(ctx, "ecr-public")
    # Runs before the stack delete (LIFO): CloudFormation cannot delete a repository holding images.
    ctx.on_cleanup(lambda: _delete_repository_if_present(ecr, repo_name))
    described = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"]
    assert len(described) == 1, f"expected exactly one repository named {repo_name!r}, got {described}"
    assert described[0]["repositoryName"] == repo_name, (
        f"expected repositoryName {repo_name!r}, got {described[0]['repositoryName']!r}"
    )

    # Real image push cycle: upload a config blob + an empty tar.gz layer blob,
    # then push a schema-2 manifest referencing both.
    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}}
    ).encode("utf-8")
    layer_bytes = _gzip_empty_tar()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)

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
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    ecr.put_image(
        repositoryName=repo_name,
        imageManifest=manifest_bytes.decode("utf-8"),
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag="latest",
    )

    images = ecr.describe_images(repositoryName=repo_name)["imageDetails"]
    assert len(images) == 1, f"expected exactly one image in {repo_name!r}, got {images}"
    assert "latest" in images[0].get("imageTags", []), (
        f"expected tag 'latest' on the pushed image, got tags {images[0].get('imageTags', [])}"
    )
    expected_manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    assert images[0]["imageDigest"] == expected_manifest_digest, (
        f"expected imageDigest {expected_manifest_digest!r} (sha256 of the pushed manifest "
        f"bytes), got {images[0]['imageDigest']!r}"
    )


# ===== helpers =====

def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """A ctx client for ``service`` pinned to ``region``: ecr-public (and CloudFormation's
    AWS::ECR::PublicRepository) is served only from us-east-1, and ctx.client keeps the
    target's endpoint, so one code path serves AWS and an emulator."""
    return ctx.client(service, region=region)


def _gzip_empty_tar() -> bytes:
    import gzip
    import io

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(b"")
    return buf.getvalue()


def _upload_blob(ecr, repo_name: str, blob: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
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
    return digest


def _delete_repository_if_present(ecr, name):
    """Teardown: force-delete the repository, tolerating one already gone."""
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _deploy_cfn(ctx, template: str) -> str:
    cfn = _regional_client(ctx, "cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-ecrpub-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})  # fits the 60 s cleanup budget

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return stack_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

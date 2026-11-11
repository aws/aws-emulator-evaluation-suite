"""delete-repository-requires-force-when-not-empty."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_if_present(ecr, name))
    return resp["repository"]

def _delete_repo_if_present(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _upload_layer(ecr, repo_name, data):
    """InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload; returns (digest, size)."""
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest, len(data)

def _build_manifest(layer_digest, layer_size, config_digest, config_size):
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    return json.dumps(manifest)

def _push_image(ecr, repo_name, tag=None, seed=b"layer-data"):
    """Push a minimally valid Docker Schema-2 image; returns the image dict from PutImage."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, seed)
    config_seed = b'{"architecture":"amd64","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config_seed)
    manifest_str = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    kwargs = {"repositoryName": repo_name, "imageManifest": manifest_str}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]

CHECK = "delete-repository-requires-force-when-not-empty"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Positive control: DeleteRepository on an empty repository succeeds outright. Negative: the
    identical call on a non-empty repository is rejected with RepositoryNotEmptyException and the
    repository remains describable; force=True then clears the precondition and removes it."""
    ecr = ctx.client("ecr")

    empty_name = ctx.unique_name("sim2real-behav-ecr-repo-empty-")
    _create_repo(ecr, ctx, empty_name)
    resp = ecr.delete_repository(repositoryName=empty_name)
    assert resp["repository"]["repositoryName"] == empty_name, (
        f"expected DeleteRepository to echo {empty_name!r}, got {resp['repository']!r}"
    )
    code, code_msg = _error(lambda: ecr.describe_repositories(repositoryNames=[empty_name]))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    expected_msg = f"The repository with name '{empty_name}' does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    _push_image(ecr, name, tag="v1")

    code, code_msg = _error(lambda: ecr.delete_repository(repositoryName=name))
    assert code == "RepositoryNotEmptyException", f"expected RepositoryNotEmptyException, got {code}"
    expected_msg = f"The repository with name '{name}' in registry with id '{ctx.account}' cannot be deleted because it still contains images"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    still_there = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert still_there[0]["repositoryName"] == name, "non-empty repo must survive the rejected delete"

    ecr.delete_repository(repositoryName=name, force=True)
    code, code_msg = _error(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    expected_msg = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

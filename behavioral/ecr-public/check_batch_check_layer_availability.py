"""batch-check-layer-availability."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-check-layer-availability"
GROUP = 'image-data-plane'
SERVICES = ['ecr-public']

def _delete_if_exists(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    kwargs.setdefault("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, name))
    return name, resp


def _err(fn):
    """Call fn(), which must fail; return its (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes) -> str:
    """Initiate -> UploadPart -> Complete for a single blob; return its sha256 digest."""
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchCheckLayerAvailability reports AVAILABLE with the uploaded size for a real layer and a
    failure for a never-uploaded digest; after repository deletion, it and an independent read
    both fail RepositoryNotFoundException."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    layer_bytes = b"batch-check-layer-availability-blob" + bytes(range(16))
    real_digest = _upload_blob(ecr, name, layer_bytes)
    fake_digest = "sha256:" + "0" * 64

    resp = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[real_digest, fake_digest]
    )
    layers_by_digest = {layer["layerDigest"]: layer for layer in resp["layers"]}
    available = {digest: layer["layerAvailability"] for digest, layer in layers_by_digest.items()}
    assert available.get(real_digest) == "AVAILABLE", available
    assert layers_by_digest[real_digest].get("layerSize") == len(layer_bytes), layers_by_digest[real_digest]

    failure_digests = [f["layerDigest"] for f in resp.get("failures", [])]
    assert fake_digest in failure_digests or available.get(fake_digest) == "UNAVAILABLE", resp

    ecr.delete_repository(repositoryName=name, force=True)
    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"The repository with name '{name}' does not exist in the registry with id '{account}'"
    )

    code, message = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == not_found, f"DescribeRepositories message: {message!r}"

    code, message = _err(
        lambda: ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[real_digest])
    )
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
    assert message == not_found, f"BatchCheckLayerAvailability message: {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""complete-layer-upload-empty."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-layer-upload-empty"
GROUP = 'error-semantics'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(), which must fail; return its (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, name))
    return name, resp


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteLayerUpload on an upload with no parts is refused EmptyUploadException with the
    exact message and its digest is not available, while a fresh upload of real bytes completes
    and is AVAILABLE at the exact size."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    empty_upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    fake_digest = "sha256:" + "1" * 64

    account = ctx.client("sts").get_caller_identity()["Account"]
    code, message = _err(
        lambda: ecr.complete_layer_upload(
            repositoryName=name, uploadId=empty_upload_id, layerDigests=[fake_digest]
        )
    )
    assert code == "EmptyUploadException", f"expected EmptyUploadException, got {code}"
    assert message == (
        f"The upload with id '{empty_upload_id}' in the repository with name '{name}' in registry "
        f"with id '{account}' cannot be completed because it does not have any parts"
    ), f"EmptyUploadException message: {message!r}"

    # --- effect-absent: the digest never entered the blob store -----------------------------
    availability = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[fake_digest])
    failure_digests = [f["layerDigest"] for f in availability.get("failures", [])]
    reported = {layer["layerDigest"]: layer["layerAvailability"] for layer in availability["layers"]}
    assert fake_digest in failure_digests or reported.get(fake_digest) == "UNAVAILABLE", (
        f"a digest that was never uploaded (CompleteLayerUpload was rejected) reports available: "
        f"{availability!r}"
    )

    # --- positive control / restore: a FRESH upload with real bytes still succeeds ----------
    blob = b"sim2real-behav-ecrpub-complete-layer-upload-empty-" + name.encode()
    real_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    recovered_upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    assert recovered_upload_id != empty_upload_id, "InitiateLayerUpload minted the same uploadId twice"
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=recovered_upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    completed = ecr.complete_layer_upload(
        repositoryName=name, uploadId=recovered_upload_id, layerDigests=[real_digest]
    )
    assert completed["layerDigest"] == real_digest, (
        f"expected layerDigest {real_digest!r} echoed back, got {completed!r}"
    )

    # --- B1: independent read at the destination, not the mutating call's own response ------
    final = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[real_digest])
    matching = [lay for lay in final["layers"] if lay["layerDigest"] == real_digest]
    assert matching and matching[0]["layerAvailability"] == "AVAILABLE", (
        f"the recovered layer is not AVAILABLE at BatchCheckLayerAvailability: {final!r}"
    )
    assert matching[0]["layerSize"] == len(blob), (
        f"layerSize is {matching[0]['layerSize']!r}, expected {len(blob)} bytes actually uploaded"
    )

    ecr.delete_repository(repositoryName=name, force=True)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""upload-layer-part-offset-gap-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upload-layer-part-offset-gap-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr-public']

def _error(fn):
    """Return the botocore Error dict from fn(); raise if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {resp!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)

    def _cleanup():
        try:
            ecr.delete_repository(repositoryName=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name, resp


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadLayerPart rejects a part not contiguous with bytes already received
    (InvalidLayerPartException); completing with only the first part reports exactly its size."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    blob = b"x" * 32
    blob_digest = "sha256:" + hashlib.sha256(blob).hexdigest()

    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]

    first = ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    assert first["lastByteReceived"] == len(blob) - 1, (
        f"lastByteReceived after the first part read {first['lastByteReceived']!r}, expected "
        f"{len(blob) - 1}"
    )

    # Received bytes end at 32; a part starting at 1000 leaves a hole.
    gap = _error(
        lambda: ecr.upload_layer_part(
            repositoryName=name,
            uploadId=upload_id,
            partFirstByte=1000,
            partLastByte=1000 + len(blob) - 1,
            layerPartBlob=blob,
        )
    )
    expected = ("InvalidLayerPartException", f"First byte of the layer part is 1000 instead of {len(blob)}")
    assert (gap.get("Code"), gap.get("Message")) == expected, f"expected {expected}, got {gap!r}"

    # Had the gapped part been accepted, the digest would mismatch or the size would read 1032.
    completed = ecr.complete_layer_upload(
        repositoryName=name, uploadId=upload_id, layerDigests=[blob_digest]
    )
    assert completed["layerDigest"] == blob_digest, (
        f"CompleteLayerUpload reported digest {completed['layerDigest']!r}; the gap-free bytes "
        f"actually accepted hash to {blob_digest!r}"
    )
    availability = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[blob_digest]
    )
    assert not availability.get("failures"), (
        f"BatchCheckLayerAvailability reported failures for {blob_digest!r}: {availability!r}"
    )
    layer = availability["layers"][0]
    assert layer["layerAvailability"] == "AVAILABLE", f"the completed layer reads {layer!r}"
    assert layer["layerSize"] == len(blob), (
        f"layerSize read {layer['layerSize']!r}; exactly {len(blob)} bytes were ever accepted -- "
        f"a bigger number would mean the gapped part was silently merged into the ledger"
    )

    ecr.delete_repository(repositoryName=name, force=True)
    gone = _error(lambda: ecr.describe_repositories(repositoryNames=[name]))
    expected = (
        "RepositoryNotFoundException",
        f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'",
    )
    assert (gone.get("Code"), gone.get("Message")) == expected, (
        f"expected the deleted repository to read {expected}, got {gone!r}"
    )
    mutate = _error(lambda: ecr.initiate_layer_upload(repositoryName=name))
    expected = (
        "RepositoryNotFoundException",
        f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'",
    )
    assert (mutate.get("Code"), mutate.get("Message")) == expected, (
        f"InitiateLayerUpload against the deleted repository should fail with {expected}, got {mutate!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

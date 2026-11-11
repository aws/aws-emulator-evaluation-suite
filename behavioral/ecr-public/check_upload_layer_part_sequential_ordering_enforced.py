"""upload-layer-part-sequential-ordering-enforced."""
from __future__ import annotations

import hashlib
import os

from behavioral_harness import tags

CHECK = "upload-layer-part-sequential-ordering-enforced"
GROUP = "ordering"
SERVICES = ["ecr-public"]

_PART_A_SIZE = 5 * 1024 * 1024  # documented minimum layer part size (5 MiB) for a non-final part
_PART_B_SIZE = 4096  # final part, allowed to be smaller than the minimum


def _ecrpub_client(ctx):
    """ecr-public is served only from us-east-1, so pin that region."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadLayerPart rejects an out-of-order part (InvalidLayerPartException) rather than
    buffering it; parts sent in order complete with the digest of the full concatenation."""
    ecrp = _ecrpub_client(ctx)

    repo_name = ctx.unique_name("sim2real-layerorder-")
    ecrp.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    part_a = os.urandom(_PART_A_SIZE)
    part_b = os.urandom(_PART_B_SIZE)
    full_layer = part_a + part_b
    expected_digest = "sha256:" + hashlib.sha256(full_layer).hexdigest()

    upload_id = ecrp.initiate_layer_upload(repositoryName=repo_name)["uploadId"]

    err = _error(
        lambda: ecrp.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload_id,
            partFirstByte=_PART_A_SIZE,
            partLastByte=_PART_A_SIZE + _PART_B_SIZE - 1,
            layerPartBlob=part_b,
        )
    )
    expected = ("InvalidLayerPartException", f"First byte of the layer part is {_PART_A_SIZE} instead of 0")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    ecrp.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=_PART_A_SIZE - 1,
        layerPartBlob=part_a,
    )
    ecrp.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=_PART_A_SIZE,
        partLastByte=_PART_A_SIZE + _PART_B_SIZE - 1,
        layerPartBlob=part_b,
    )

    complete = ecrp.complete_layer_upload(
        repositoryName=repo_name,
        uploadId=upload_id,
        layerDigests=[expected_digest],
    )
    assert complete["layerDigest"] == expected_digest, (
        "CompleteLayerUpload must accept the digest of the sequentially-ordered "
        "concatenation of correctly-ordered UploadLayerPart calls"
    )

    availability = ecrp.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[expected_digest]
    )
    assert availability["failures"] == []
    assert len(availability["layers"]) == 1
    layer = availability["layers"][0]
    assert layer["layerDigest"] == expected_digest
    assert layer["layerAvailability"] == "AVAILABLE"
    assert layer["layerSize"] == len(full_layer)


def _error(fn):
    """Return the botocore Error dict from fn(); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

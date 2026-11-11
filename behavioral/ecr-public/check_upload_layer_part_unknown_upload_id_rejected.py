"""upload-layer-part-unknown-upload-id-rejected."""
from __future__ import annotations

import hashlib
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upload-layer-part-unknown-upload-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadLayerPart on a never-issued uploadId is refused UploadNotFoundException with the
    exact message, and the real session it did not address still completes with its layer
    AVAILABLE."""
    ecr = ctx.client("ecr-public")
    name = ctx.unique_name("sim2real-behav-ecrp-badupload-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: _force_delete_repository(ecr, name))

    blob = b"some-bytes"
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()

    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]

    # Positive control: the real, in-flight uploadId accepts the part.
    put = ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    assert put["lastByteReceived"] == len(blob) - 1, (
        f"the positive control did not accept the part: {put!r}"
    )

    # Break: a well-formed uploadId this repository never issued.
    never_issued = str(uuid.uuid4())
    error = _client_error(
        lambda: ecr.upload_layer_part(
            repositoryName=name,
            uploadId=never_issued,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
    )
    expected = (
        "UploadNotFoundException",
        f"The upload with id '{never_issued}' in the repository with name '{name}' in registry with id "
        f"'{ctx.account}' does not exist",
    )
    assert (error.get("Code"), error.get("Message")) == expected, (
        f"expected {expected} for a never-issued uploadId, got {error!r}"
    )

    # Effect-absent, via an independent op at the destination: the legitimate session the
    # never-issued id was not addressed to is untouched and still completes.
    complete = ecr.complete_layer_upload(
        repositoryName=name, uploadId=upload_id, layerDigests=[digest]
    )
    assert complete["layerDigest"] == digest, (
        f"the legitimate session did not complete cleanly after the rejected call: {complete!r}"
    )
    avail = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[digest])
    assert not avail["failures"], f"unexpected failures: {avail['failures']}"
    assert avail["layers"][0]["layerAvailability"] == "AVAILABLE", (
        f"layer not available after completion: {avail['layers'][0]!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING an unrelated uploadId real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected UploadLayerPart to be rejected, but it succeeded: {result!r}")


def _force_delete_repository(ecr, name: str) -> None:
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""complete-layer-upload-digest-mismatch-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-layer-upload-digest-mismatch-rejected"
GROUP = 'overly-permissive'
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteLayerUpload with a layerDigest that is not the sha256 of the uploaded bytes is
    refused InvalidLayerException with the exact message and commits neither digest, while a
    fresh upload completed with the true digest is AVAILABLE at the exact size."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    blob = b"real-layer-bytes-" * 4
    true_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    lying_digest = "sha256:" + hashlib.sha256(b"totally-different-bytes").hexdigest()
    assert lying_digest != true_digest, "test setup bug: lying digest collided with the real one"

    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )

    code, message = _err(
        lambda: ecr.complete_layer_upload(
            repositoryName=name, uploadId=upload_id, layerDigests=[lying_digest]
        )
    )
    assert code == "InvalidLayerException", f"expected InvalidLayerException, got {code}"
    assert message == "None of the provided layer digests match the calculated layer digest", (
        f"InvalidLayerException message: {message!r}"
    )

    # Effect absent: a store that ignored the mismatch would have committed under `lying_digest`;
    # one that "helpfully" corrected it would have committed under `true_digest`. Neither may be
    # AVAILABLE after the rejection.
    avail = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[true_digest, lying_digest]
    )
    by_digest = {layer["layerDigest"]: layer for layer in avail.get("layers", [])}
    for digest in (true_digest, lying_digest):
        entry = by_digest.get(digest)
        if entry is not None:
            assert entry["layerAvailability"] != "AVAILABLE", (
                f"{digest} became AVAILABLE after a rejected CompleteLayerUpload: {entry}"
            )

    # Positive control: identical bytes, honest digest, fresh upload session -> AVAILABLE at the
    # exact size. Without this, "rejects a mismatched digest" is indistinguishable from "rejects
    # every CompleteLayerUpload".
    upload_id2 = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    assert upload_id2 != upload_id, "InitiateLayerUpload reused an uploadId"
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id2,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    done = ecr.complete_layer_upload(
        repositoryName=name, uploadId=upload_id2, layerDigests=[true_digest]
    )
    assert done["layerDigest"] == true_digest, (
        f"CompleteLayerUpload returned {done.get('layerDigest')}, expected {true_digest}"
    )

    avail2 = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[true_digest, lying_digest]
    )
    layers2 = {layer["layerDigest"]: layer for layer in avail2["layers"]}
    good = layers2[true_digest]
    assert good["layerAvailability"] == "AVAILABLE", f"control layer not AVAILABLE: {good}"
    assert good["layerSize"] == len(blob), (
        f"layerSize {good['layerSize']} != uploaded byte count {len(blob)}"
    )
    bad = layers2.get(lying_digest)
    if bad is not None:
        assert bad["layerAvailability"] != "AVAILABLE", (
            f"the mismatched digest is AVAILABLE after the control upload: {bad}"
        )

    ecr.delete_repository(repositoryName=name, force=True)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

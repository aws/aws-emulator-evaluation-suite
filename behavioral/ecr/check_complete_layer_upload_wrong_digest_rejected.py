"""complete-layer-upload-wrong-digest-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    """Force-delete the repository, then poll until it is reported gone."""
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ecr.describe_repositories(repositoryNames=[name])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
                return
        time.sleep(1.0)
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

CHECK = "complete-layer-upload-wrong-digest-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteLayerUpload rejects a well-formed digest that does not match the uploaded bytes
    (InvalidLayerException), leaving neither digest AVAILABLE; the honest digest then succeeds."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]

    payload = b"sim2real-ecr-layer-integrity-payload-0001"
    true_digest = _sha256_digest(payload)
    # A valid sha256, but of different content than the bytes uploaded.
    wrong_digest = _sha256_digest(payload + b"!")
    assert wrong_digest != true_digest, (
        f"test setup bug: wrong_digest {wrong_digest!r} == true_digest {true_digest!r}"
    )

    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    assert isinstance(upload_id, str) and upload_id, f"no uploadId: {upload_id!r}"
    part = ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(payload) - 1,
        layerPartBlob=payload,
    )
    assert part["uploadId"] == upload_id, f"uploadId not echoed: {part}"
    assert part["lastByteReceived"] == len(payload) - 1, (
        f"lastByteReceived {part.get('lastByteReceived')} != {len(payload) - 1}"
    )

    code, message = _error(
        lambda: ecr.complete_layer_upload(
            repositoryName=name, uploadId=upload_id, layerDigests=[wrong_digest]
        )
    )
    assert code == "InvalidLayerException", (
        f"expected InvalidLayerException for a digest that does not match the uploaded "
        f"bytes, got {code}"
    )
    expected = "None of the provided layer digests match the calculated layer digest"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Neither ignoring the mismatch nor correcting the digest may commit the layer.
    avail = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[true_digest, wrong_digest]
    )
    by_digest = {layer["layerDigest"]: layer for layer in avail.get("layers", [])}
    for digest in (true_digest, wrong_digest):
        entry = by_digest.get(digest)
        if entry is not None:
            assert entry["layerAvailability"] != "AVAILABLE", (
                f"{digest} became AVAILABLE after a rejected CompleteLayerUpload: {entry}"
            )

    upload_id2 = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    assert upload_id2 != upload_id, "InitiateLayerUpload reused an uploadId"
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id2,
        partFirstByte=0,
        partLastByte=len(payload) - 1,
        layerPartBlob=payload,
    )
    done = ecr.complete_layer_upload(
        repositoryName=name, uploadId=upload_id2, layerDigests=[true_digest]
    )
    assert done["layerDigest"] == true_digest, (
        f"CompleteLayerUpload returned {done.get('layerDigest')}, expected {true_digest}"
    )

    avail2 = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[true_digest, wrong_digest]
    )
    layers2 = {layer["layerDigest"]: layer for layer in avail2["layers"]}
    good = layers2[true_digest]
    assert good["layerAvailability"] == "AVAILABLE", f"control layer not AVAILABLE: {good}"
    assert good["layerSize"] == len(payload), (
        f"layerSize {good['layerSize']} != uploaded byte count {len(payload)}"
    )
    bad = layers2.get(wrong_digest)
    if bad is not None:
        assert bad["layerAvailability"] != "AVAILABLE", (
            f"the mismatched digest is AVAILABLE after the control upload: {bad}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

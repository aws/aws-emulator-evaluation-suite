"""upload-layer-part-noncontiguous-range-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

# _error_struct: awsJson1_1 merges modeled exception members into exc.response, so it
# exposes the WHOLE error body -- which for InvalidLayerPartException is message only.


def _error_struct(fn):
    """Return (code, full error response dict). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response
    raise AssertionError(
        f"expected InvalidLayerPartException but the call SUCCEEDED and returned {result!r}"
    )


def _repository_gone(ecr, name):
    """True once DescribeRepositories reports RepositoryNotFoundException for name."""
    try:
        ecr.describe_repositories(repositoryNames=[name])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
            return True
        raise
    return False


def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository with a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _repository_gone(ecr, name):
            return
        time.sleep(1.0)
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()



CHECK = "upload-layer-part-noncontiguous-range-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadLayerPart rejects a part not contiguous with the previous one with
    InvalidLayerPartException whose message names the rejected and expected offsets, and no
    layer materialises; a single contiguous upload of the same bytes becomes AVAILABLE."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]

    part1 = b"P1" * 64          # 128 bytes, offsets 0..127
    part2 = b"P2" * 64          # would legitimately occupy 128..255
    full = part1 + part2
    full_digest = _sha256_digest(full)

    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    first = ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(part1) - 1,
        layerPartBlob=part1,
    )
    assert first["lastByteReceived"] == len(part1) - 1, (
        f"lastByteReceived after part 1 is {first.get('lastByteReceived')}, expected {len(part1) - 1}"
    )

    # An 8-byte hole between part 1 and part 2.
    gap_first = len(part1) + 8
    code, err = _error_struct(
        lambda: ecr.upload_layer_part(
            repositoryName=name,
            uploadId=upload_id,
            partFirstByte=gap_first,
            partLastByte=gap_first + len(part2) - 1,
            layerPartBlob=part2,
        )
    )
    assert code == "InvalidLayerPartException", (
        f"expected InvalidLayerPartException for a part starting at {gap_first} after "
        f"{len(part1)} bytes received, got {code}"
    )
    # AWS leaves InvalidLayerPartException's modeled members (uploadId, lastValidByteReceived)
    # unset; the resumption offsets are carried only in the message.
    message = err.get("Error", {}).get("Message")
    expected_message = f"First byte of the layer part is {gap_first} instead of {len(part1)}"
    assert message == expected_message, (
        f"InvalidLayerPartException message {message!r} is not the exact byte-range diagnostic "
        f"{expected_message!r}: it must name the rejected first byte {gap_first} and the expected "
        f"next byte {len(part1)} (lastValidByteReceived {len(part1) - 1} + 1) for a client to resume"
    )

    # Neither the full-content digest nor the accepted-prefix digest may be available.
    prefix_digest = _sha256_digest(part1)
    avail = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[full_digest, prefix_digest]
    )
    for layer in avail.get("layers", []):
        assert layer["layerAvailability"] != "AVAILABLE", (
            f"{layer['layerDigest']} is AVAILABLE from an uncompleted, gapped upload: {layer}"
        )

    # Single-part on purpose: ECR enforces a 5 MiB minimum on every part but the last
    # (LayerPartTooSmallException), so a small legitimate multi-part upload is not possible.
    upload_id2 = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    second = ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id2,
        partFirstByte=0,
        partLastByte=len(full) - 1,
        layerPartBlob=full,
    )
    assert second["lastByteReceived"] == len(full) - 1, (
        f"lastByteReceived for the whole-layer part is {second.get('lastByteReceived')}, "
        f"expected {len(full) - 1}"
    )
    done = ecr.complete_layer_upload(
        repositoryName=name, uploadId=upload_id2, layerDigests=[full_digest]
    )
    assert done["layerDigest"] == full_digest, (
        f"CompleteLayerUpload returned {done.get('layerDigest')}, expected {full_digest}"
    )
    layers = {
        layer["layerDigest"]: layer
        for layer in ecr.batch_check_layer_availability(
            repositoryName=name, layerDigests=[full_digest]
        )["layers"]
    }
    good = layers[full_digest]
    assert good["layerAvailability"] == "AVAILABLE", f"control layer not AVAILABLE: {good}"
    assert good["layerSize"] == len(full), (
        f"layerSize {good['layerSize']} != {len(full)}; the committed layer is not exactly "
        f"the uploaded byte range"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

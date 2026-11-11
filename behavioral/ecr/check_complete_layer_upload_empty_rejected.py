"""complete-layer-upload-empty-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


CHECK = "complete-layer-upload-empty-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteLayerUpload with no uploaded part is refused EmptyUploadException with the exact
    message and commits nothing under the claimed digest, while a fresh upload of real bytes to
    the same repository completes AVAILABLE."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]

    fake_digest = "sha256:" + ("c" * 64)
    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    assert isinstance(upload_id, str) and upload_id, f"no uploadId: {upload_id!r}"

    code, message = _error(
        lambda: ecr.complete_layer_upload(
            repositoryName=name, uploadId=upload_id, layerDigests=[fake_digest]
        )
    )
    assert code == "EmptyUploadException", f"expected EmptyUploadException, got {code}"
    expected = (
        f"The upload with id '{upload_id}' in the repository with name '{name}' in registry "
        f"with id '{ctx.account}' cannot be completed because it does not have any parts"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing got committed under the digest we (falsely) claimed to complete.
    avail = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[fake_digest])
    by_digest = {layer["layerDigest"]: layer for layer in avail.get("layers", [])}
    entry = by_digest.get(fake_digest)
    if entry is not None:
        assert entry["layerAvailability"] != "AVAILABLE", (
            f"{fake_digest} became AVAILABLE after a rejected empty CompleteLayerUpload: {entry}"
        )

    # Control: a fresh upload session with a real uploaded part on the same repository must
    # still succeed.
    payload = b"sim2real-ecr-empty-upload-control-payload-0001"
    true_digest = _sha256_digest(payload)
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
    avail2 = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[true_digest])
    layers2 = {layer["layerDigest"]: layer for layer in avail2["layers"]}
    good = layers2[true_digest]
    assert good["layerAvailability"] == "AVAILABLE", f"control layer not AVAILABLE: {good}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

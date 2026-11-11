"""layer-upload-lifecycle-complete."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

CHECK = "layer-upload-lifecycle-complete"
GROUP = 'image-data-plane'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload makes the layer
    AVAILABLE (via BatchCheckLayerAvailability), and completing the same uploadId again
    fails with UploadNotFoundException."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    data = f"layer-{ctx.unique_name('')}".encode()
    digest = _sha256_digest(data)

    init = ecr.initiate_layer_upload(repositoryName=name)
    upload_id = init["uploadId"]
    assert init["partSize"] > 0, f"expected a positive partSize, got {init.get('partSize')!r}"

    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    complete = ecr.complete_layer_upload(
        repositoryName=name, uploadId=upload_id, layerDigests=[digest]
    )
    assert complete["layerDigest"] == digest, (
        f"expected completed layerDigest {digest!r}, got {complete.get('layerDigest')!r}"
    )

    avail = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[digest])
    assert avail["layers"][0]["layerAvailability"] == "AVAILABLE", (
        f"expected layer {digest!r} AVAILABLE, got {avail['layers'][0]['layerAvailability']!r}"
    )

    code, message = _error(
        lambda: ecr.complete_layer_upload(
            repositoryName=name, uploadId=upload_id, layerDigests=[digest]
        )
    )
    assert code == "UploadNotFoundException", (
        f"expected re-completion of a consumed uploadId to be rejected with "
        f"UploadNotFoundException, got {code!r}"
    )
    assert message == (
        f"The upload with id '{upload_id}' in the repository with name '{name}' in registry with id '{ctx.account}' does not exist"
    ), message

    # The rejected re-completion must not have disturbed the layer that already landed.
    avail_after = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[digest])
    assert avail_after["layers"][0]["layerAvailability"] == "AVAILABLE", (
        f"expected layer {digest!r} to remain AVAILABLE after the rejected re-completion, "
        f"got {avail_after['layers'][0]['layerAvailability']!r}"
    )
    assert not avail_after["failures"], (
        f"expected no failures reported for {digest!r}, got {avail_after['failures']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

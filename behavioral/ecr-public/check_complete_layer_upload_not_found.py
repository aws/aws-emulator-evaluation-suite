"""complete-layer-upload-not-found."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-layer-upload-not-found"
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
    kwargs.setdefault("tags", [{"Key": "sim2real-behav", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, name))
    return name, resp


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteLayerUpload refuses a malformed uploadId with InvalidParameterException and a
    well-formed UUID that was never issued with UploadNotFoundException, each with the exact
    message, while an issued uploadId completes and its layer is AVAILABLE."""
    ecr = ctx.client("ecr-public")
    import uuid as _uuid

    name, _ = _create_repository(ctx, ecr)

    # Positive control — a real InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload
    # must succeed, and the layer must then be independently readable at the destination.
    control_blob = b"complete-layer-upload-not-found-control-blob" + bytes(range(8))
    control_digest = _sha256_digest(control_blob)
    control_upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=control_upload_id,
        partFirstByte=0,
        partLastByte=len(control_blob) - 1,
        layerPartBlob=control_blob,
    )
    complete_resp = ecr.complete_layer_upload(
        repositoryName=name, uploadId=control_upload_id, layerDigests=[control_digest]
    )
    assert complete_resp["layerDigest"] == control_digest, (
        f"expected CompleteLayerUpload to echo {control_digest}, got {complete_resp.get('layerDigest')}"
    )
    avail_resp = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[control_digest])
    available = {l["layerDigest"]: l["layerAvailability"] for l in avail_resp["layers"]}
    assert available.get(control_digest) == "AVAILABLE", (
        f"expected {control_digest} AVAILABLE via independent read, got {avail_resp}"
    )

    fake_digest = "sha256:" + "2" * 64

    # (a) Malformed uploadId — fails parameter validation before any lookup.
    malformed_code, malformed_message = _err(
        lambda: ecr.complete_layer_upload(
            repositoryName=name, uploadId="bogus-upload-id-does-not-exist", layerDigests=[fake_digest]
        )
    )
    assert malformed_code == "InvalidParameterException", (
        f"expected InvalidParameterException for malformed uploadId, got {malformed_code}"
    )
    assert malformed_message == (
        "Invalid parameter at 'uploadId' failed to satisfy constraint: 'Member must satisfy "
        "regular expression pattern: "
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'"
    ), f"InvalidParameterException message: {malformed_message!r}"

    # (b) Well-formed UUID that was never issued by InitiateLayerUpload.
    never_issued = str(_uuid.uuid4())
    notfound_code, notfound_message = _err(
        lambda: ecr.complete_layer_upload(
            repositoryName=name, uploadId=never_issued, layerDigests=[fake_digest]
        )
    )
    assert notfound_code == "UploadNotFoundException", (
        f"expected UploadNotFoundException for unissued uploadId, got {notfound_code}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert notfound_message == (
        f"The upload with id '{never_issued}' in the repository with name '{name}' in registry "
        f"with id '{account}' does not exist"
    ), f"UploadNotFoundException message: {notfound_message!r}"

    ecr.delete_repository(repositoryName=name, force=True)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

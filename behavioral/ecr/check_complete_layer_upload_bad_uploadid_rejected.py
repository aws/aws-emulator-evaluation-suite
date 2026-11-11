"""complete-layer-upload-bad-uploadid-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    kwargs.setdefault("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

CHECK = "complete-layer-upload-bad-uploadid-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteLayerUpload with an uploadId the repository never issued MUST fail with
    UploadNotFoundException (distinct resource-scoped not-found from repository lookups),
    and must leave no layer committed under the digest that call named."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)

    # Positive control: prove CompleteLayerUpload actually works against this repository/
    # account before trusting a rejection from it — otherwise "rejects a bad uploadId" is
    # indistinguishable from "rejects every CompleteLayerUpload call".
    control_payload = f"control-{ctx.unique_name('')}".encode()
    control_digest = _sha256_digest(control_payload)
    control_upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=control_upload_id,
        partFirstByte=0,
        partLastByte=len(control_payload) - 1,
        layerPartBlob=control_payload,
    )
    control_complete = ecr.complete_layer_upload(
        repositoryName=name, uploadId=control_upload_id, layerDigests=[control_digest]
    )
    assert control_complete["layerDigest"] == control_digest, (
        f"control CompleteLayerUpload returned {control_complete.get('layerDigest')}, "
        f"expected {control_digest}"
    )
    control_avail = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[control_digest]
    )
    assert control_avail["layers"][0]["layerAvailability"] == "AVAILABLE", (
        f"control layer never became AVAILABLE: {control_avail}"
    )

    # An uploadId this repository never issued -- syntactically a valid UUID, but not one
    # InitiateLayerUpload ever returned -- can never become valid, so this negative has no
    # restore leg by construction.
    fake_digest = "sha256:" + ("d" * 64)
    fake_upload_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(
        lambda: ecr.complete_layer_upload(
            repositoryName=name,
            uploadId=fake_upload_id,
            layerDigests=[fake_digest],
        )
    )
    assert code == "UploadNotFoundException", f"expected UploadNotFoundException, got {code}"
    expected = (
        f"The upload with id '{fake_upload_id}' in the repository with name '{name}' in "
        f"registry with id '{ctx.account}' does not exist"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read at the destination confirms no layer landed under
    # the digest the rejected call named.
    avail = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[fake_digest])
    by_digest = {layer["layerDigest"]: layer for layer in avail.get("layers", [])}
    entry = by_digest.get(fake_digest)
    if entry is not None:
        assert entry["layerAvailability"] != "AVAILABLE", (
            f"{fake_digest} became AVAILABLE despite the rejected CompleteLayerUpload: {entry}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

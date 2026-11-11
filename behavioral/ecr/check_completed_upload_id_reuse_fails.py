"""completed-upload-id-reuse-fails."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "completed-upload-id-reuse-fails"
GROUP = 'error-semantics'
SERVICES = ['ecr']

def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, name=None, **kwargs):
    """Create a repository, register its (forced) teardown, and return the repository dict."""
    ecr = ctx.client("ecr")
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _upload_layer(ctx, repo_name, data):
    """Upload a single-part layer; returns (layerDigest, uploadId)."""
    ecr = ctx.client("ecr")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    init = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = init["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    complete = ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    assert complete["layerDigest"] == digest, complete
    return digest, upload_id


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a layer upload completes (digest AVAILABLE), UploadLayerPart on the consumed uploadId
    is rejected with UploadNotFoundException rather than accepting more bytes."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    data = f"layer-{ctx.unique_name('sim2real-behav-')}".encode()
    digest, upload_id = _upload_layer(ctx, name, data)

    avail = ecr.batch_check_layer_availability(repositoryName=name, layerDigests=[digest])
    assert avail["layers"][0]["layerAvailability"] == "AVAILABLE", avail

    more_data = f"more-{ctx.unique_name('sim2real-behav-')}".encode()
    code, message = _error(
        lambda: ecr.upload_layer_part(
            repositoryName=name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(more_data) - 1,
            layerPartBlob=more_data,
        )
    )
    assert code == "UploadNotFoundException", code
    expected = (
        f"The upload with id '{upload_id}' in the repository with name '{name}' in registry "
        f"with id '{ctx.account}' does not exist"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

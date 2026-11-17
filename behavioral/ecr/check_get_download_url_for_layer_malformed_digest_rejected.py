"""get-download-url-for-layer-malformed-digest-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


CHECK = "get-download-url-for-layer-malformed-digest-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDownloadUrlForLayer with a layerDigest missing the required 'algorithm:hex' form is
    rejected with InvalidParameterException; a real uploaded layer's digest succeeds."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    data = b"sim2real-ecr-malformed-digest-layer"
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=name, uploadId=upload_id, layerDigests=[digest])

    ok = ecr.get_download_url_for_layer(repositoryName=name, layerDigest=digest)
    assert ok["layerDigest"] == digest, f"expected the positive control to echo {digest!r}, got {ok}"

    malformed = digest.replace(":", "-", 1)
    expected = (
        "Invalid parameter at 'layerDigest' failed to satisfy constraint: 'Member must "
        "satisfy regular expression pattern: [a-zA-Z0-9-_+.]+:[a-fA-F0-9]+'"
    )
    code, message = _error(
        lambda: ecr.get_download_url_for_layer(repositoryName=name, layerDigest=malformed)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

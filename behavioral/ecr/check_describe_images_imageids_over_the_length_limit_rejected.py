"""describe-images-imageids-over-the-length-limit-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _upload_blob(ecr, repo_name, data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name, uploadId=upload_id,
        partFirstByte=0, partLastByte=len(data) - 1, layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest, len(data)


CHECK = "describe-images-imageids-over-the-length-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeImages accepts an imageIds list of exactly 100 entries but refuses 101 with
    InvalidParameterException, the model's fixed, non-adjustable list-length constant.
    """
    ecr = ctx.client("ecr")
    repo = ctx.unique_name("sim2real-behav-ecr-repo-")
    ecr.create_repository(repositoryName=repo, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo, force=True))

    layer_digest, layer_size = _upload_blob(ecr, repo, b"sim2real-describe-images-limit-layer\n")
    config = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {}, "history": []}, sort_keys=True
    ).encode()
    config_digest, config_size = _upload_blob(ecr, repo, config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": config_size, "digest": config_digest,
            },
            "layers": [{
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size, "digest": layer_digest,
            }],
        },
        sort_keys=True,
    )
    tag = "sim2real-limit"
    pushed_digest = ecr.put_image(
        repositoryName=repo, imageManifest=manifest, imageTag=tag
    )["image"]["imageId"]["imageDigest"]

    # The same real imageId repeated: only the LIST LENGTH changes between the two calls below, so
    # a refusal at 101 cannot be existence or duplication, only the count.
    at_limit = [{"imageTag": tag}] * 100
    ok = ecr.describe_images(repositoryName=repo, imageIds=at_limit)
    returned_digests = {d["imageDigest"] for d in ok["imageDetails"]}
    assert returned_digests == {pushed_digest}, (
        f"DescribeImages with 100 (repeated, valid) imageIds returned digests "
        f"{sorted(returned_digests)}, expected only the pushed digest {pushed_digest!r}"
    )

    over_limit = [{"imageTag": tag}] * 101
    code, message = _error(lambda: ecr.describe_images(repositoryName=repo, imageIds=over_limit))
    assert code == "InvalidParameterException", (
        f"DescribeImages with 101 imageIds answered {code!r}, expected InvalidParameterException"
    )
    expected_message = (
        "Invalid parameter at 'imageIds' failed to satisfy constraint: "
        "'Member must have length less than or equal to 100'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The positive control above is unaffected: the identical in-bound call still succeeds.
    ok_again = ecr.describe_images(repositoryName=repo, imageIds=at_limit)
    assert {d["imageDigest"] for d in ok_again["imageDetails"]} == {pushed_digest}, (
        "the 100-entry call stopped succeeding after the 101-entry call was refused"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

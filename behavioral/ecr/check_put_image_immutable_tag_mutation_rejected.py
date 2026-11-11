"""put-image-immutable-tag-mutation-rejected."""
from __future__ import annotations

import gzip
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-image-immutable-tag-mutation-rejected"
GROUP = "data-plane"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On an IMMUTABLE repository, pushing new content under an existing tag raises
    ImageTagAlreadyExistsException and keeps the original digest, a new tag still pushes, and
    of several concurrent pushes to one fresh tag exactly one wins."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-immutable-")
    ecr.create_repository(
        repositoryName=repo_name,
        imageTagMutability="IMMUTABLE",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    layer_bytes, layer_digest, config_bytes, config_digest = _prepare_shared_blobs(ecr, repo_name)

    digest_a = _push_variant(ecr, repo_name, layer_bytes, layer_digest, config_bytes, config_digest, "stable", "a")

    code, message = _error_code(
        lambda: _push_variant(ecr, repo_name, layer_bytes, layer_digest, config_bytes, config_digest, "stable", "b")
    )
    assert code == "ImageTagAlreadyExistsException", f"expected ImageTagAlreadyExistsException, got {code!r}"
    expected_message = (
        f"The image tag 'stable' already exists in the '{repo_name}' repository and cannot be overwritten "
        f"because the tag is immutable."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    current = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "stable"}])["imageDetails"]
    assert len(current) == 1 and current[0]["imageDigest"] == digest_a, "tag must still point at the original digest"

    digest_b = _push_variant(
        ecr, repo_name, layer_bytes, layer_digest, config_bytes, config_digest, "stable-v2", "b"
    )
    assert digest_b != digest_a, f"positive control under a fresh tag must produce a distinct digest, got {digest_b!r} == digest_a"

    race_results = []
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [
            pool.submit(_race_push, ecr, repo_name, layer_bytes, layer_digest, config_bytes, config_digest, f"racer-{i}")
            for i in range(5)
        ]
        for fut in as_completed(futures):
            race_results.append(fut.result())

    successes = [r for r in race_results if r[0] == "ok"]
    failures = [r for r in race_results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly one racer to win the shared tag, got {successes!r}"
    assert len(failures) == 4, f"expected the other 4 racers to be rejected, got {failures!r}"
    expected_race_message = (
        f"The image tag 'race-tag' already exists in the '{repo_name}' repository and cannot be overwritten "
        f"because the tag is immutable."
    )
    assert all(
        error == ("ImageTagAlreadyExistsException", expected_race_message) for _, error in failures
    ), (
        f"expected every losing racer to fail with ImageTagAlreadyExistsException and message "
        f"{expected_race_message!r}, got {failures!r}"
    )

    winner_digest = successes[0][1]
    final = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "race-tag"}])["imageDetails"]
    assert len(final) == 1 and final[0]["imageDigest"] == winner_digest, (
        f"expected race-tag to resolve to the winner's digest {winner_digest!r}, got {final!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this push to be rejected, but it SUCCEEDED and returned {result!r}")


def _prepare_shared_blobs(ecr, repository_name: str):
    layer_bytes = gzip.compress(b"", mtime=0)
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"").hexdigest()]},
            "history": [],
        }
    ).encode()
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    for blob, digest in ((layer_bytes, layer_digest), (config_bytes, config_digest)):
        upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
        ecr.upload_layer_part(
            repositoryName=repository_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        ecr.complete_layer_upload(repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest])
    return layer_bytes, layer_digest, config_bytes, config_digest


def _push_variant(ecr, repository_name, layer_bytes, layer_digest, config_bytes, config_digest, tag, marker):
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
        "annotations": {"sim2real.variant": marker},
    }
    resp = ecr.put_image(
        repositoryName=repository_name,
        imageManifest=json.dumps(manifest),
        imageManifestMediaType=manifest["mediaType"],
        imageTag=tag,
    )
    return resp["image"]["imageId"]["imageDigest"]


def _race_push(ecr, repository_name, layer_bytes, layer_digest, config_bytes, config_digest, marker):
    try:
        digest = _push_variant(
            ecr, repository_name, layer_bytes, layer_digest, config_bytes, config_digest, "race-tag", marker
        )
        return ("ok", digest)
    except ClientError as e:
        return ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

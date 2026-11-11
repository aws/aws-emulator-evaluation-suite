"""concurrent-immutable-tag-push-race."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

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

def _upload_layer(ecr, repo_name, data):
    """Upload a single-part layer; returns (digest, size)."""
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest, len(data)

def _build_manifest(layer_digest, layer_size, config_digest, config_size):
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    return json.dumps(manifest)

def _push_image(ecr, repo_name, tag=None, seed=b"layer-data"):
    """Push a minimally valid Docker Schema-2 image; returns the image dict from PutImage."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, seed)
    config_seed = b'{"architecture":"amd64","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config_seed)
    manifest_str = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    kwargs = {"repositoryName": repo_name, "imageManifest": manifest_str}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]

CHECK = "concurrent-immutable-tag-push-race"
GROUP = 'concurrency'
SERVICES = ['ecr']
ERR_IMAGE_TAG_ALREADY_EXISTS = 'ImageTagAlreadyExistsException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On an IMMUTABLE repository, of N concurrent PutImage calls of different content under one
    new tag exactly one wins, the rest fail with ImageTagAlreadyExistsException."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name, imageTagMutability="IMMUTABLE")
    tag = "race"
    n = 5

    def racer(i):
        return lambda: _push_image(ecr, name, tag=tag, seed=f"racer-{i}".encode())

    results = _run_concurrent([racer(i) for i in range(n)], timeout_s=90)
    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes == 1, f"expected exactly 1 winner, got {successes} winners (codes={codes})"
    assert codes.count(ERR_IMAGE_TAG_ALREADY_EXISTS) == n - 1, (
        f"expected {n - 1} losers rejected with {ERR_IMAGE_TAG_ALREADY_EXISTS}, got codes={codes}"
    )
    winner_digest = next(r["imageId"]["imageDigest"] for r in results if not isinstance(r, BaseException))

    listed = ecr.list_images(repositoryName=name)["imageIds"]
    tagged = [i for i in listed if i.get("imageTag") == tag]
    assert len(tagged) == 1, f"expected exactly 1 image tagged {tag!r}, got {tagged}"
    assert tagged[0]["imageDigest"] == winner_digest, (
        f"the tagged image's digest {tagged[0]['imageDigest']!r} does not match the digest "
        f"{winner_digest!r} that PutImage reported as the winner"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""replicated-image-is-byte-identical-in-the-destination-region."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


DOCKER_V2 = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"

DEST_TIMEOUT_S = 240.0


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(ecr, name):
    """Force-delete name; an already-absent repository is fine, any other refusal raises."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ecr.exceptions.RepositoryNotFoundException:
        pass


def _repo_absent(ecr, name):
    try:
        ecr.describe_repositories(repositoryNames=[name])
    except ecr.exceptions.RepositoryNotFoundException:
        return True
    return False


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _gzip_tar(entries):
    """A deterministic gzip(tar) rootfs layer; returns (gzipped, uncompressed)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path, payload in entries:
            info = tarfile.TarInfo(name=path)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(payload))
    uncompressed = raw.getvalue()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(uncompressed)
    return buf.getvalue(), uncompressed


def _upload_blob(ecr, repo_name, data):
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    done = ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    assert done["layerDigest"] == digest, (
        f"CompleteLayerUpload committed {done.get('layerDigest')!r} for bytes hashing to {digest!r}"
    )
    return digest, len(data)


def _create_repo(ecr, ctx, name, scenario):
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": scenario}]
    )
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=45):
    try:
        _delete_if_present(ecr, name)
    except ClientError as exc:
        print(f"LEAK: delete_repository({name}, force=True) failed with {exc!r}")
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _repo_absent(ecr, name):
            return
        time.sleep(1.0)
    print(f"LEAK: repository {name} still present {timeout_s}s after force delete")
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _delete_replicated_repo(ecr_dest, name):
    """Delete the repository ECR created in the destination Region, retrying because the delete can
    race replication still in flight."""
    deadline = time.monotonic() + 40.0
    while time.monotonic() < deadline:
        try:
            _delete_if_present(ecr_dest, name)
            return
        except ClientError:
            time.sleep(3.0)
    print(f"LEAK: destination-Region repository {name} could not be deleted")
    raise AssertionError(f"could not delete destination-Region repository {name}")


def _http_get(ctx, url):
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(_routed_request(ctx, url), timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() if hasattr(exc, "read") else b""
    except urllib.error.URLError as exc:
        raise AssertionError(f"the presigned layer URL {url[:120]} is unreachable: {exc}") from exc


CHECK = "replicated-image-is-byte-identical-in-the-destination-region"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data", "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """Cross-Region replication auto-creates a same-named repository in the destination Region with
    a byte-identical manifest (same digest) and a layer blob served there with the source digest,
    while a repository outside the prefix filter is never replicated."""
    ecr = ctx.client("ecr")
    account = ctx.client("sts").get_caller_identity()["Account"]
    dest_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    assert dest_region != ctx.region, (
        f"the destination Region {dest_region!r} must differ from the source {ctx.region!r}"
    )
    ecr_dest = ctx.client("ecr", region=dest_region)

    # The replication configuration is a per-registry singleton, so restore whatever was there;
    # PutReplicationConfiguration accepts an empty rules list.
    previous_rules = ecr.describe_registry()["replicationConfiguration"]["rules"]
    ctx.on_cleanup(
        lambda: ecr.put_replication_configuration(
            replicationConfiguration={"rules": previous_rules}
        )
    )

    replicated_name = ctx.unique_name("sim2real-ecr-repl-yes-")
    unfiltered_name = ctx.unique_name("sim2real-ecr-repl-no-")
    assert not unfiltered_name.startswith(replicated_name), (
        "the control repository name must not fall under the replicated prefix"
    )

    ecr.put_replication_configuration(
        replicationConfiguration={
            "rules": [
                {
                    "destinations": [{"region": dest_region, "registryId": account}],
                    "repositoryFilters": [
                        {"filter": replicated_name, "filterType": "PREFIX_MATCH"}
                    ],
                }
            ]
        }
    )
    echoed = ecr.describe_registry()["replicationConfiguration"]["rules"]
    assert len(echoed) == 1 and echoed[0]["destinations"][0]["region"] == dest_region, (
        f"DescribeRegistry reports rules {echoed!r} after configuring one rule to {dest_region!r}; "
        f"the rest of this check would be measuring an unconfigured registry"
    )

    # The rule must exist BEFORE the push: only content pushed after replication is configured is
    # replicated (Considerations for private image replication).
    _create_repo(ecr, ctx, replicated_name, "replication-destination")
    _create_repo(ecr, ctx, unfiltered_name, "replication-control")
    ctx.on_cleanup(lambda: _delete_replicated_repo(ecr_dest, replicated_name))

    layer_gz, layer_raw = _gzip_tar([("sim2real/replicated.txt", b"ecr-cross-region\n")])
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "history": [],
            "rootfs": {"type": "layers", "diff_ids": [_sha256_digest(layer_raw)]},
        },
        sort_keys=True,
    ).encode()

    manifests = {}
    # The control is pushed first, so once the filtered image arrives the control has had strictly
    # more time to replicate; its absence then reflects the filter, not a short wait.
    for repo_name in (unfiltered_name, replicated_name):
        layer_digest, layer_size = _upload_blob(ecr, repo_name, layer_gz)
        config_digest, config_size = _upload_blob(ecr, repo_name, config)
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": DOCKER_V2,
                "config": {
                    "mediaType": DOCKER_CONFIG,
                    "size": config_size,
                    "digest": config_digest,
                },
                "layers": [
                    {"mediaType": DOCKER_LAYER, "size": layer_size, "digest": layer_digest}
                ],
            },
            sort_keys=True,
        )
        expected = _sha256_digest(manifest.encode())
        put = ecr.put_image(
            repositoryName=repo_name,
            imageManifest=manifest,
            imageManifestMediaType=DOCKER_V2,
            imageTag="replicated",
        )
        assert put["image"]["imageId"]["imageDigest"] == expected, (
            f"PutImage into {repo_name!r} minted {put['image']['imageId']['imageDigest']!r} for a "
            f"manifest whose bytes hash to {expected!r}; a registry is content-addressed"
        )
        manifests[repo_name] = (manifest, expected, layer_digest)

    source_manifest, source_digest, source_layer_digest = manifests[replicated_name]
    push_at = time.monotonic()

    # Read through the destination Region's own client; replication typically completes within
    # minutes, hence the bounded poll.
    deadline = push_at + DEST_TIMEOUT_S
    dest_detail = None
    last_seen = None
    while time.monotonic() < deadline:
        try:
            dest_detail = ecr_dest.describe_images(
                repositoryName=replicated_name, imageIds=[{"imageTag": "replicated"}]
            )["imageDetails"][0]
            break
        except ClientError as exc:
            last_seen = exc.response.get("Error", {}).get("Code")
            if last_seen not in ("RepositoryNotFoundException", "ImageNotFoundException"):
                raise
        time.sleep(5.0)
    if dest_detail is None:
        raise AssertionError(
            f"replication never produced image tag 'replicated' in repository "
            f"{replicated_name!r} in {dest_region!r} within {DEST_TIMEOUT_S}s; last error code "
            f"{last_seen!r}"
        )
    latency_s = time.monotonic() - push_at

    # Replication auto-creates the destination repository under the same name.
    dest_repo = ecr_dest.describe_repositories(repositoryNames=[replicated_name])["repositories"][0]
    assert dest_repo["repositoryName"] == replicated_name, (
        f"the destination-Region repository is named {dest_repo.get('repositoryName')!r}; "
        f"replication must keep the name {replicated_name!r} across Regions"
    )
    assert dest_repo["repositoryArn"].split(":")[3] == dest_region, (
        f"the destination repository ARN {dest_repo.get('repositoryArn')!r} does not name Region "
        f"{dest_region!r}; the second client is not reading the destination Region"
    )
    assert dest_detail["imageDigest"] == source_digest, (
        f"the replicated image has digest {dest_detail.get('imageDigest')!r} in {dest_region!r} "
        f"but {source_digest!r} at the source; a replicator that re-serialises the manifest breaks "
        f"every digest a signer or admission controller pinned"
    )
    assert dest_detail["imageTags"] == ["replicated"], (
        f"the destination image carries tags {dest_detail.get('imageTags')!r}, expected exactly "
        f"['replicated']"
    )

    dest_fetched = ecr_dest.batch_get_image(
        repositoryName=replicated_name, imageIds=[{"imageDigest": source_digest}]
    )
    assert dest_fetched.get("failures", []) == [], (
        f"BatchGetImage in {dest_region!r} could not read the replicated manifest: "
        f"{dest_fetched.get('failures')!r}"
    )
    assert dest_fetched["images"][0]["imageManifest"] == source_manifest, (
        f"the manifest served in {dest_region!r} differs from the bytes pushed at the source: "
        f"{dest_fetched['images'][0]['imageManifest'][:300]!r}"
    )

    # The layer must be downloadable in the destination Region and hash to the source digest.
    dest_url = ecr_dest.get_download_url_for_layer(
        repositoryName=replicated_name, layerDigest=source_layer_digest
    )["downloadUrl"]
    status, blob = _http_get(ctx, dest_url)
    assert status == 200, (
        f"the destination Region's presigned layer URL returned HTTP {status!r}: {blob[:200]!r}"
    )
    assert _sha256_digest(blob) == source_layer_digest, (
        f"the layer served in {dest_region!r} hashes to {_sha256_digest(blob)!r}, but the source "
        f"committed it as {source_layer_digest!r}; the blob was not replicated intact"
    )
    assert gzip.decompress(blob) == layer_raw, (
        f"the replicated layer does not gunzip to the original tar in {dest_region!r} "
        f"({len(blob)} bytes served)"
    )

    # The unmatched repository stays absent over a short extra hold; at least 10s so the 5s cadence
    # takes two or more observations.
    hold_s = min(max(3.0 * latency_s, 10.0), 45.0)
    window_started = time.monotonic()
    observations = 0
    while True:
        error = _client_error(
            lambda: ecr_dest.describe_repositories(repositoryNames=[unfiltered_name])
        )
        assert error == {
            "Code": "RepositoryNotFoundException",
            "Message": (
                f"The repository with name '{unfiltered_name}' does not exist in the registry "
                f"with id '{account}'"
            ),
        }, (
            f"DescribeRepositories in {dest_region!r} answered {error!r} for {unfiltered_name!r}, "
            f"which no replication rule selects; expected RepositoryNotFoundException. The "
            f"control was pushed BEFORE the replicated image, which arrived in {latency_s:.1f}s, "
            f"so the delivery path is demonstrated and this is a filter failure, not slowness"
        )
        observations += 1
        if time.monotonic() - window_started >= hold_s:
            break
        time.sleep(5.0)
    assert observations >= 2, (
        f"only {observations} observation(s) of the control's absence over "
        f"{time.monotonic() - window_started:.1f}s; at least two are needed for the absence to be "
        f"a held state rather than a single sample"
    )

    # The destination Region's listing must agree.
    listed = set()
    for page in ecr_dest.get_paginator("describe_repositories").paginate():
        listed.update(r["repositoryName"] for r in page["repositories"])
    assert unfiltered_name not in listed, (
        f"{unfiltered_name!r} appears in the destination Region's repository listing despite "
        f"matching no replication filter"
    )
    assert replicated_name in listed, (
        f"{replicated_name!r} is missing from the destination Region's repository listing even "
        f"though DescribeRepositories resolved it by name; the list operation and the get disagree"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""e2e-replication-configuration-drives-replication-status."""
from __future__ import annotations

import gzip
import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-replication-configuration-drives-replication-status"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """Prefix-scoped cross-Region replication drives DescribeImageReplicationStatus for a pushed
    image to COMPLETE in the destination Region, observed from the source Region's API."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    # Replication needs a destination Region distinct from ctx.region.
    destination_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"

    # The replication configuration is an account-wide singleton; restore it afterwards.
    original_rules = ecr.describe_registry()["replicationConfiguration"]["rules"]
    ctx.on_cleanup(lambda: ecr.put_replication_configuration(replicationConfiguration={"rules": original_rules}))

    repo_name = ctx.unique_name("sim2real-ecr-repl-")
    new_rules = [
        {
            "destinations": [{"region": destination_region, "registryId": account_id}],
            "repositoryFilters": [{"filter": repo_name, "filterType": "PREFIX_MATCH"}],
        }
    ]
    ecr.put_replication_configuration(replicationConfiguration={"rules": new_rules})

    ecr.create_repository(repositoryName=repo_name)
    repo_deleted = {"done": False}

    def _cleanup_repo():
        if repo_deleted["done"]:
            return
        try:
            ecr.delete_repository(repositoryName=repo_name, force=True)
        except ecr.exceptions.RepositoryNotFoundException:
            pass

    ctx.on_cleanup(_cleanup_repo)

    tag = "repl-target"
    _push_minimal_image(ecr, repo_name, tag)
    image_id = {"imageTag": tag}

    terminal = {"COMPLETE", "FAILED"}
    matching: list = []
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        resp = ecr.describe_image_replication_status(repositoryName=repo_name, imageId=image_id)
        matching = [s for s in resp["replicationStatuses"] if s["region"] == destination_region]
        if matching and matching[0]["status"] in terminal:
            break
        time.sleep(2)

    assert len(matching) == 1, f"expected exactly one status entry for {destination_region}, got {matching!r}"
    assert matching[0]["status"] == "COMPLETE", f"replication did not complete: {matching[0]!r}"

    ecr.delete_repository(repositoryName=repo_name, force=True)
    repo_deleted["done"] = True
    try:
        ecr.describe_repositories(repositoryNames=[repo_name])
        raise AssertionError(f"expected {repo_name} to be gone after delete_repository")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code}"
        expected = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _push_minimal_image(ecr, repository_name: str, tag: str) -> str:
    layer_bytes = gzip.compress(b"", mtime=0)
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"").hexdigest()]},
        "history": [],
    }
    config_bytes = json.dumps(config).encode()
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
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repository_name,
        imageManifest=json.dumps(manifest),
        imageManifestMediaType=manifest["mediaType"],
        imageTag=tag,
    )
    return resp["image"]["imageId"]["imageDigest"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

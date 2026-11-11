"""list-image-referrers-ordering-by-artifact-type."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-image-referrers-ordering-by-artifact-type"
GROUP = "ordering"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListImageReferrers applies filter.artifactTypes server-side: a single-type filter returns
    only that type's referrer, a subset filter excludes unnamed types, and results are stable."""
    ecr = ctx.client("ecr")
    repo = ctx.unique_name("sim2real-behav-ref-order-")
    ecr.create_repository(repositoryName=repo)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo, force=True))

    empty_bytes = b"{}"
    empty_digest = _upload_blob(ctx, repo, empty_bytes)

    subj_layer_bytes = b"subject-ordering-payload"
    subj_layer_digest = _upload_blob(ctx, repo, subj_layer_bytes)
    subject_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": empty_digest,
            "size": len(empty_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": subj_layer_digest,
                "size": len(subj_layer_bytes),
            }
        ],
    }
    subject_text = json.dumps(subject_manifest, separators=(",", ":"))
    subject_push = ecr.put_image(
        repositoryName=repo, imageManifest=subject_text, imageTag="subject"
    )
    subject_digest = subject_push["image"]["imageId"]["imageDigest"]

    artifact_types = [
        "application/vnd.sim2real.type-a+json",
        "application/vnd.sim2real.type-b+json",
        "application/vnd.sim2real.type-c+json",
    ]
    digest_by_type: dict[str, str] = {}
    for i, atype in enumerate(artifact_types):
        layer_bytes = f"referrer-payload-{i}".encode("utf-8")
        layer_digest = _upload_blob(ctx, repo, layer_bytes)
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": atype,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": empty_digest,
                "size": len(empty_bytes),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.sim2real.referrer.layer.v1+json",
                    "digest": layer_digest,
                    "size": len(layer_bytes),
                }
            ],
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": subject_digest,
                "size": len(subject_text.encode("utf-8")),
            },
        }
        text = json.dumps(manifest, separators=(",", ":"))
        push = ecr.put_image(repositoryName=repo, imageManifest=text)
        digest_by_type[atype] = push["image"]["imageId"]["imageDigest"]

    def fetch(filter_types: list[str] | None = None) -> list[dict[str, Any]]:
        kwargs: dict[str, Any] = {
            "repositoryName": repo,
            "subjectId": {"imageDigest": subject_digest},
        }
        if filter_types is not None:
            kwargs["filter"] = {"artifactTypes": filter_types}
        return ecr.list_image_referrers(**kwargs).get("referrers", [])

    all_referrers = _poll_until(
        lambda: fetch(), lambda rs: len(rs) >= 3, timeout_s=30.0, interval_s=2.0
    )
    assert len(all_referrers) == 3, (
        f"expected all 3 pushed referrers visible before filtering, got "
        f"{[r['digest'] for r in all_referrers]!r}"
    )
    assert {r["digest"] for r in all_referrers} == set(digest_by_type.values()), (
        f"unfiltered ListImageReferrers must return exactly the pushed referrers: "
        f"expected {set(digest_by_type.values())!r}, got "
        f"{[r['digest'] for r in all_referrers]!r}"
    )

    # filter.artifactTypes to a single type must select only that type's referrer,
    # at the destination -- not a hint the server is free to ignore.
    single_type = artifact_types[1]
    filtered_once = fetch([single_type])
    assert {r["digest"] for r in filtered_once} == {digest_by_type[single_type]}, (
        f"filter.artifactTypes=[{single_type!r}] must return exactly that referrer "
        f"({digest_by_type[single_type]!r}), got "
        f"{[r['digest'] for r in filtered_once]!r}"
    )
    assert all(r["artifactType"] == single_type for r in filtered_once), (
        f"every referrer returned under filter.artifactTypes=[{single_type!r}] must "
        f"report that artifactType, got "
        f"{[r.get('artifactType') for r in filtered_once]!r}"
    )

    # A filtered result must be stable across repeated calls with no intervening writes.
    filtered_twice = fetch([single_type])
    assert [r["digest"] for r in filtered_once] == [r["digest"] for r in filtered_twice], (
        f"a filtered ListImageReferrers call must return a stable result across "
        f"repeated calls: {[r['digest'] for r in filtered_once]!r} vs "
        f"{[r['digest'] for r in filtered_twice]!r}"
    )

    # filter.artifactTypes to a subset must exclude every type not named, not just
    # include the ones that are.
    kept_types = [artifact_types[0], artifact_types[2]]
    excluded_type = artifact_types[1]
    filtered_pair = fetch(kept_types)
    assert {r["digest"] for r in filtered_pair} == {
        digest_by_type[t] for t in kept_types
    }, (
        f"filter.artifactTypes={kept_types!r} must return exactly the referrers of "
        f"those types ({[digest_by_type[t] for t in kept_types]!r}), got "
        f"{[r['digest'] for r in filtered_pair]!r}"
    )
    assert digest_by_type[excluded_type] not in {r["digest"] for r in filtered_pair}, (
        f"filter.artifactTypes={kept_types!r} must exclude the referrer of type "
        f"{excluded_type!r} ({digest_by_type[excluded_type]!r}), but it was present "
        f"in {[r['digest'] for r in filtered_pair]!r}"
    )


def _upload_blob(ctx, repo: str, data: bytes) -> str:
    ecr = ctx.client("ecr")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(f"condition not met within {timeout_s}s (last: {result!r})")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""image-pushed-at-is-a-live-clock-stamp-that-reads-do-not-move."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "image-pushed-at-is-a-live-clock-stamp-that-reads-do-not-move"
GROUP = "representation"
SERVICES = ["ecr-public"]

OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"

# Clock-skew allowance on each side of the measured bracket. Both this host and the service run
# NTP, so a correct stamp cannot be minutes out; 120 s is generous enough to never flake and still
# rejects epoch 0, a hardcoded date, and a stamp taken at read time more than two minutes later.
_SKEW_S = 120.0

_DESCRIBE_BUDGET_S = 60.0
_DESCRIBE_INTERVAL_S = 2.0
# The two reads of the first image's stamp are separated by real work (the second push), never a
# sleep; exact equality then distinguishes a push-time stamp from a read-time now().


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that raises on exhaustion rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} was not observed within {timeout_s}s; last read was {last!r}"
    )


def _ecr_public(ctx):
    """ECR Public's control plane is served only from us-east-1; elsewhere every operation answers
    UnsupportedCommandException, so the client is region-pinned."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    name = name or ctx.unique_name("sim2real-behav-ecrpub-clock-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes) -> str:
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _describe_all_images(ecr, repository_name):
    details = []
    for page in ecr.get_paginator("describe_images").paginate(repositoryName=repository_name):
        details.extend(page["imageDetails"])
    return details


def _manifest_for(repo, salt, layer_digest, layer_len, config_bytes, config_digest) -> str:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "size": len(config_bytes),
                "digest": config_digest,
            },
            "layers": [
                {"mediaType": OCI_LAYER_MEDIA_TYPE, "size": layer_len, "digest": layer_digest}
            ],
            "annotations": {"sim2real.salt": salt, "sim2real.repo": repo},
        },
        separators=(",", ":"),
    )


def _push(ecr, repo, tag, salt, layer_digest, layer_len):
    """Push one image and return (digest, t_before, t_after) bracketing the PutImage call."""
    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "salt": salt}, separators=(",", ":")
    ).encode()
    config_digest = _upload_blob(ecr, repo, config_bytes)
    manifest = _manifest_for(repo, salt, layer_digest, layer_len, config_bytes, config_digest)
    digest = _sha256_digest(manifest.encode())
    before = datetime.now(timezone.utc)
    stored = ecr.put_image(
        repositoryName=repo,
        imageManifest=manifest,
        imageManifestMediaType=OCI_MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    )["image"]
    after = datetime.now(timezone.utc)
    assert stored["imageId"]["imageDigest"] == digest, (
        f"PutImage computed {stored['imageId']['imageDigest']!r} for a manifest whose sha256 is "
        f"{digest!r}"
    )
    return digest, before, after, len(manifest.encode())


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """imagePushedAt is stamped from the live clock at push time, does not move when re-read, and is
    reported identically by DescribeImages and DescribeImageTags."""
    ecr = _ecr_public(ctx)
    name, _ = _create_repository(ctx, ecr)

    layer_bytes = b"sim2real-clock-layer-" + name.encode() + bytes(range(80))
    layer_digest = _upload_blob(ecr, name, layer_bytes)

    first_digest, first_before, first_after, _ = _push(
        ecr, name, "clock-first", "first", layer_digest, len(layer_bytes)
    )

    described = _poll_until(
        lambda: {d["imageDigest"]: d for d in _describe_all_images(ecr, name)},
        lambda by_digest: first_digest in by_digest,
        timeout_s=_DESCRIBE_BUDGET_S,
        interval_s=_DESCRIBE_INTERVAL_S,
        description=f"DescribeImages reporting the first image {first_digest}",
    )
    first_detail = described[first_digest]
    first_pushed_at = first_detail["imagePushedAt"]
    assert first_pushed_at.tzinfo is not None, (
        f"imagePushedAt came back naive ({first_pushed_at!r}); botocore parses a timestamp member "
        f"into a tz-aware datetime, so a naive value means the target sent something unparseable "
        f"as a timestamp"
    )

    # --- bracketed by the live clock ------------------------------------------------------------
    lower = first_before - timedelta(seconds=_SKEW_S)
    upper = first_after + timedelta(seconds=_SKEW_S)
    assert lower <= first_pushed_at <= upper, (
        f"imagePushedAt {first_pushed_at.isoformat()} is outside the PutImage window "
        f"[{first_before.isoformat()}, {first_after.isoformat()}] widened by {_SKEW_S}s of clock "
        f"skew -- a fixed or epoch stamp lands here"
    )

    # --- DescribeImageTags reports the same numbers -------------------------------------------
    tag_details = ecr.describe_image_tags(repositoryName=name)["imageTagDetails"]
    by_tag = {t["imageTag"]: t for t in tag_details}
    assert "clock-first" in by_tag, (
        f"DescribeImageTags listed {sorted(by_tag)}, missing 'clock-first'"
    )
    nested = by_tag["clock-first"]["imageDetail"]
    assert nested["imageDigest"] == first_digest, (
        f"DescribeImageTags resolved 'clock-first' to {nested['imageDigest']!r}, "
        f"expected {first_digest!r}"
    )
    assert nested["imagePushedAt"] == first_pushed_at, (
        f"DescribeImageTags reports imagePushedAt {nested['imagePushedAt']!r} while DescribeImages "
        f"reports {first_pushed_at!r} for the same digest -- one store must not have two answers"
    )
    assert nested["imageSizeInBytes"] == first_detail["imageSizeInBytes"], (
        f"DescribeImageTags reports imageSizeInBytes {nested['imageSizeInBytes']} while "
        f"DescribeImages reports {first_detail['imageSizeInBytes']} for the same digest"
    )
    assert nested["imageManifestMediaType"] == first_detail["imageManifestMediaType"], (
        f"DescribeImageTags reports imageManifestMediaType "
        f"{nested.get('imageManifestMediaType')!r} while DescribeImages reports "
        f"{first_detail.get('imageManifestMediaType')!r} for the same digest"
    )
    assert nested["imageManifestMediaType"] == OCI_MANIFEST_MEDIA_TYPE, (
        f"the pushed manifest's media type came back as "
        f"{nested.get('imageManifestMediaType')!r}, expected {OCI_MANIFEST_MEDIA_TYPE!r}"
    )

    # --- the TAG's own createdAt is also a live stamp ---------------------------------------
    created_at = by_tag["clock-first"]["createdAt"]
    assert lower <= created_at <= upper, (
        f"the tag's createdAt {created_at.isoformat()} is outside the PutImage window "
        f"[{first_before.isoformat()}, {first_after.isoformat()}] widened by {_SKEW_S}s"
    )

    # --- a second, later push. Real work separates the two stamps; no sleep. -----------------
    second_digest, second_before, second_after, _ = _push(
        ecr, name, "clock-second", "second", layer_digest, len(layer_bytes)
    )
    assert second_digest != first_digest, (
        "the two pushes must produce distinct manifests for the ordering assertion to mean anything"
    )
    described2 = _poll_until(
        lambda: {d["imageDigest"]: d for d in _describe_all_images(ecr, name)},
        lambda by_digest: {first_digest, second_digest} <= set(by_digest),
        timeout_s=_DESCRIBE_BUDGET_S,
        interval_s=_DESCRIBE_INTERVAL_S,
        description=f"DescribeImages reporting both {first_digest} and {second_digest}",
    )
    second_pushed_at = described2[second_digest]["imagePushedAt"]
    second_lower = second_before - timedelta(seconds=_SKEW_S)
    second_upper = second_after + timedelta(seconds=_SKEW_S)
    assert second_lower <= second_pushed_at <= second_upper, (
        f"the second image's imagePushedAt {second_pushed_at.isoformat()} is outside its own "
        f"PutImage window [{second_before.isoformat()}, {second_after.isoformat()}] widened by "
        f"{_SKEW_S}s"
    )
    assert first_pushed_at <= second_pushed_at, (
        f"the image pushed SECOND is stamped {second_pushed_at.isoformat()}, earlier than the "
        f"first's {first_pushed_at.isoformat()}; push stamps must not run backwards"
    )

    # --- freeze detector: The first image's stamp must not have moved. -------------------
    elapsed = (second_after - first_after).total_seconds()
    assert elapsed > 0, (
        f"the two reads of the first image's stamp were {elapsed:.3f}s apart; they must be "
        f"separated by real time or the freeze detector compares one read with itself"
    )
    reread = described2[first_digest]["imagePushedAt"]
    assert reread == first_pushed_at, (
        f"the first image's imagePushedAt read {first_pushed_at.isoformat()} and then "
        f"{reread.isoformat()} {elapsed:.2f}s later -- it is being evaluated at READ time, not "
        f"stamped at push time"
    )
    # A third read, immediately, for a three-sample freeze rather than two.
    third = {d["imageDigest"]: d for d in _describe_all_images(ecr, name)}[first_digest][
        "imagePushedAt"
    ]
    assert third == first_pushed_at, (
        f"a third read of the first image's imagePushedAt returned {third.isoformat()}, not the "
        f"{first_pushed_at.isoformat()} the previous two reads returned"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

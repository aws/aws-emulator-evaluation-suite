"""describe-image-tags-pagination-partitions-the-tag-set-exactly."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-image-tags-pagination-partitions-the-tag-set-exactly"
GROUP = "representation"
SERVICES = ["ecr-public"]

OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"

_TAG_COUNT = 5
_PAGE_SIZE = 2

# Read-after-write on a freshly pushed set of five tags. Exhaustion RAISES: a registry that never
# lists what it accepted is the defect this check exists to catch, never an environment problem.
_LIST_BUDGET_S = 60.0
_LIST_INTERVAL_S = 2.0


# Every byte pushed here is synthetic: an ECR Public repository is world-visible on
# gallery.ecr.aws for as long as it exists.


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


def _error_code(fn, *, what: str):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"{what} succeeded; it must have been refused")


def _ecr_public(ctx):
    """ECR Public's control plane is served only from us-east-1; elsewhere every operation answers
    UnsupportedCommandException, so the client is region-pinned."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-page-")
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


def _walk_pages(call, items_key, *, page_size):
    """Walk nextToken by hand, not via botocore's paginator, which would hide an ignored maxResults.
    Returns the list of raw page responses."""
    pages = []
    token = None
    # A hard cap on iterations so a target that returns the same token forever fails loudly
    # instead of hanging: with page_size >= 1 no correct target can need more pages than items.
    for _ in range(64):
        kwargs = {"maxResults": page_size}
        if token is not None:
            kwargs["nextToken"] = token
        resp = call(**kwargs)
        pages.append(resp)
        token = resp.get("nextToken")
        if not token:
            return pages
        assert len(resp[items_key]) > 0, (
            f"a page carrying nextToken {token!r} returned zero {items_key} -- a token that "
            f"promises more must be backed by more"
        )
    raise AssertionError(
        f"pagination over {items_key} did not terminate in 64 pages; the target is reissuing a "
        f"token that never advances (last token {token!r})"
    )


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """maxResults/nextToken really partition DescribeImageTags and DescribeImages: pages are
    capped at maxResults, their union is exactly the unpaginated set with no duplicate, and
    re-reading a page does not advance the cursor."""
    ecr = _ecr_public(ctx)
    name, _ = _create_repository(ctx, ecr)

    # One shared layer, five DISTINCT configs -> five distinct manifests, one tag each.
    layer_bytes = b"sim2real-pagination-layer-" + name.encode()
    layer_digest = _upload_blob(ecr, name, layer_bytes)

    expected_tags = set()
    expected_digests = set()
    for i in range(_TAG_COUNT):
        config_bytes = json.dumps(
            {"architecture": "amd64", "os": "linux", "repo": name, "n": i}, separators=(",", ":")
        ).encode()
        config_digest = _upload_blob(ecr, name, config_bytes)
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "config": {
                    "mediaType": OCI_CONFIG_MEDIA_TYPE,
                    "size": len(config_bytes),
                    "digest": config_digest,
                },
                "layers": [
                    {
                        "mediaType": OCI_LAYER_MEDIA_TYPE,
                        "size": len(layer_bytes),
                        "digest": layer_digest,
                    }
                ],
            },
            separators=(",", ":"),
        )
        tag = f"page-{i}"
        pushed = ecr.put_image(
            repositoryName=name,
            imageManifest=manifest,
            imageManifestMediaType=OCI_MANIFEST_MEDIA_TYPE,
            imageTag=tag,
        )["image"]
        assert pushed["imageId"]["imageTag"] == tag, (
            f"PutImage stored tag {pushed['imageId'].get('imageTag')!r}, expected {tag!r}"
        )
        expected_tags.add(tag)
        expected_digests.add(_sha256_digest(manifest.encode()))

    assert len(expected_digests) == _TAG_COUNT, (
        f"the five manifests collided into {len(expected_digests)} digests; each must be distinct "
        f"for the partition assertions below to mean anything"
    )

    # --- the UNPAGINATED truth, established first: this is the set every page walk must reproduce
    full = _poll_until(
        lambda: {t["imageTag"] for t in ecr.describe_image_tags(repositoryName=name)[
            "imageTagDetails"
        ]},
        lambda got: got == expected_tags,
        timeout_s=_LIST_BUDGET_S,
        interval_s=_LIST_INTERVAL_S,
        description=(
            f"DescribeImageTags listing exactly {sorted(expected_tags)} for repository {name}"
        ),
    )
    assert full == expected_tags, (
        f"DescribeImageTags with no maxResults listed {sorted(full)}, expected "
        f"{sorted(expected_tags)}"
    )

    # --- the page walk over DescribeImageTags ---------------------------------------------------
    pages = _walk_pages(
        lambda **kw: ecr.describe_image_tags(repositoryName=name, **kw),
        "imageTagDetails",
        page_size=_PAGE_SIZE,
    )
    sizes = [len(p["imageTagDetails"]) for p in pages]
    assert all(size <= _PAGE_SIZE for size in sizes), (
        f"maxResults={_PAGE_SIZE} was not honoured: page sizes were {sizes} -- an emulator that "
        f"returns the whole set on page one fails exactly here"
    )
    assert sizes[0] == _PAGE_SIZE, (
        f"the first page returned {sizes[0]} of {_TAG_COUNT} tags with maxResults={_PAGE_SIZE}; a "
        f"full page was available and must have been filled"
    )
    assert pages[0].get("nextToken"), (
        f"the first page of {_TAG_COUNT} tags at maxResults={_PAGE_SIZE} carried no nextToken, so "
        f"{_TAG_COUNT - sizes[0]} tags are unreachable: {pages[0]!r}"
    )
    assert not pages[-1].get("nextToken"), (
        f"the final page carried nextToken {pages[-1].get('nextToken')!r}; the walk ended because "
        f"the items ran out, not because the target said so"
    )
    assert len(pages) >= -(-_TAG_COUNT // _PAGE_SIZE), (
        f"{_TAG_COUNT} tags at maxResults={_PAGE_SIZE} needs at least "
        f"{-(-_TAG_COUNT // _PAGE_SIZE)} pages; the walk took {len(pages)} (sizes {sizes})"
    )

    walked = [t["imageTag"] for p in pages for t in p["imageTagDetails"]]
    assert len(walked) == len(set(walked)), (
        f"the page walk returned a tag twice: {sorted(walked)}"
    )
    assert set(walked) == full, (
        f"the page walk yielded {sorted(set(walked))} but the unpaginated read yielded "
        f"{sorted(full)}; pagination must partition the set, not resample it"
    )
    assert sum(sizes) == _TAG_COUNT, (
        f"the page walk returned {sum(sizes)} tags in total, expected {_TAG_COUNT}"
    )

    # --- a read must not advance the cursor: three identical first-page reads, one answer. -----
    first_pages = [
        ecr.describe_image_tags(repositoryName=name, maxResults=_PAGE_SIZE) for _ in range(3)
    ]
    first_sets = [tuple(t["imageTag"] for t in p["imageTagDetails"]) for p in first_pages]
    assert len(set(first_sets)) == 1, (
        f"three identical DescribeImageTags(maxResults={_PAGE_SIZE}) calls returned three "
        f"different first pages {first_sets} -- a read advanced the cursor"
    )
    assert all(len(s) == _PAGE_SIZE for s in first_sets), (
        f"a repeated first page changed size: {first_sets}"
    )

    # --- the same partition invariant on DescribeImages, over digests -------------------------
    image_pages = _walk_pages(
        lambda **kw: ecr.describe_images(repositoryName=name, **kw),
        "imageDetails",
        page_size=_PAGE_SIZE,
    )
    image_sizes = [len(p["imageDetails"]) for p in image_pages]
    assert all(size <= _PAGE_SIZE for size in image_sizes), (
        f"DescribeImages ignored maxResults={_PAGE_SIZE}: page sizes were {image_sizes}"
    )
    walked_digests = [d["imageDigest"] for p in image_pages for d in p["imageDetails"]]
    assert len(walked_digests) == len(set(walked_digests)), (
        f"DescribeImages returned a digest twice across pages: {sorted(walked_digests)}"
    )
    assert set(walked_digests) == expected_digests, (
        f"the DescribeImages page walk yielded {sorted(set(walked_digests))}, expected the "
        f"{_TAG_COUNT} pushed digests {sorted(expected_digests)}"
    )

    # --- a never-issued token is refused ---------------------------------------------------------
    # The successful walk above is the positive control, so this cannot pass by refusing every token.
    forged = "c2ltMnJlYWwtbmV2ZXItaXNzdWVkLXRva2Vu"  # base64 "sim2real-never-issued-token"
    code, code_msg = _error_code(
        lambda: ecr.describe_image_tags(repositoryName=name, nextToken=forged),
        what=f"DescribeImageTags with a never-issued nextToken {forged!r}",
    )
    assert code == "InvalidParameterException", (
        f"a forged nextToken was refused {code!r}; expected InvalidParameterException, the only "
        f"input-shaped error DescribeImageTags models"
    )
    expected_code_msg = "Invalid parameter at 'NextToken' failed to satisfy constraint: 'Invalid next token provided'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"
    # ...and the forged token changed nothing: the unpaginated read still shows the full set.
    after = {t["imageTag"] for t in ecr.describe_image_tags(repositoryName=name)["imageTagDetails"]}
    assert after == expected_tags, (
        f"after a refused nextToken the repository lists {sorted(after)}, expected "
        f"{sorted(expected_tags)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

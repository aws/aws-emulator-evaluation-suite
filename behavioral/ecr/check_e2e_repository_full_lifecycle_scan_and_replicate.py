"""e2e-repository-full-lifecycle-scan-and-replicate."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-repository-full-lifecycle-scan-and-replicate"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Mirror an image through a pull-through cache rule, scan it to COMPLETE findings, delete the
    repository, and assert later describe and scan calls fail with RepositoryNotFoundException."""
    ecr = ctx.client("ecr")

    prefix = _ecr_prefix(ctx, "e2e")
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, upstreamRegistryUrl="public.ecr.aws"
    )
    ctx.on_cleanup(lambda: _safe_delete_ptc_rule(ctx, prefix))

    repo_name = f"{prefix}/amazonlinux/amazonlinux"
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": prefix}]
    )
    ctx.on_cleanup(lambda: _safe_delete_repository(ctx, repo_name))

    image = _poll_until(
        lambda: _try_batch_get_image(ecr, repo_name, "latest"),
        lambda result: result is not None,
        timeout_s=180.0,
        interval_s=5.0,
    )
    pushed_digest = image["imageId"]["imageDigest"]

    # Basic scanning cannot scan a multi-arch manifest list, and "latest" on public amazonlinux
    # usually is one, so mirror a single platform's child manifest by digest before scanning.
    manifest = json.loads(image["imageManifest"])
    scan_image_id: dict
    if manifest.get("mediaType") in (
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    ):
        child_digest = manifest["manifests"][0]["digest"]
        child_image = _poll_until(
            lambda: _try_batch_get_image_by_digest(ecr, repo_name, child_digest),
            lambda result: result is not None,
            timeout_s=60.0,
            interval_s=5.0,
        )
        scan_digest = child_image["imageId"]["imageDigest"]
        scan_image_id = {"imageDigest": scan_digest}
    else:
        scan_digest = pushed_digest
        scan_image_id = {"imageTag": "latest"}

    # The mirrored image may not be visible to StartImageScan right after BatchGetImage creates
    # it (eventual consistency), so retry the scan start.
    _poll_until(
        lambda: _try_start_image_scan(ecr, repo_name, scan_image_id),
        lambda result: result is not None,
        timeout_s=60.0,
        interval_s=5.0,
    )

    # Amazon ECR basic scanning is asynchronous and can take a few minutes to
    # complete: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-basic.html
    findings = _poll_until(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=repo_name, imageId=scan_image_id
        ),
        lambda resp: resp["imageScanStatus"]["status"] not in ("PENDING", "IN_PROGRESS"),
        timeout_s=300.0,
        interval_s=10.0,
    )

    assert findings["imageScanStatus"]["status"] == "COMPLETE", findings["imageScanStatus"]
    assert "imageScanCompletedAt" in findings["imageScanFindings"], findings["imageScanFindings"]
    severity_counts = findings["imageScanFindings"]["findingSeverityCounts"]
    assert isinstance(severity_counts, dict), severity_counts
    assert all(isinstance(v, int) for v in severity_counts.values()), severity_counts

    ecr.delete_repository(repositoryName=repo_name, force=True)

    code, message = _error(lambda: ecr.describe_repositories(repositoryNames=[repo_name]))
    assert code == "RepositoryNotFoundException", code
    expected = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # a mutation against the now-dead repository must fail the same way, not
    # silently resurrect it or operate on a stale cached handle
    rescan_code, rescan_message = _error(
        lambda: ecr.start_image_scan(repositoryName=repo_name, imageId=scan_image_id)
    )
    assert rescan_code == "RepositoryNotFoundException", rescan_code
    expected = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert rescan_message == expected, f"expected message {expected!r}, got {rescan_message!r}"
    assert pushed_digest  # sanity: we did observe a real mirrored image digest


def _ecr_prefix(ctx, tag: str) -> str:
    """Collision-free ecrRepositoryPrefix within ECR's 2-30 char alphanumeric pattern."""
    raw = ctx.unique_name(f"sim2real{tag}")
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"sim2real{tag}{digest}"[:30]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last}")


def _try_batch_get_image(ecr, repo_name: str, tag: str):
    """Pull-through mirrors are fetched synchronously on BatchGetImage; the
    first call against a cold cache can transiently fail while ECR reaches
    out to the upstream registry, or before the mirrored repo even exists."""
    try:
        resp = ecr.batch_get_image(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    except ClientError as err:
        if err.response["Error"]["Code"] in (
            "RepositoryNotFoundException",
            "UnableToGetUpstreamImageException",
        ):
            return None
        raise
    if resp["failures"] or not resp["images"]:
        return None
    return resp["images"][0]


def _try_batch_get_image_by_digest(ecr, repo_name: str, digest: str):
    try:
        resp = ecr.batch_get_image(
            repositoryName=repo_name, imageIds=[{"imageDigest": digest}]
        )
    except ClientError as err:
        if err.response["Error"]["Code"] in (
            "RepositoryNotFoundException",
            "UnableToGetUpstreamImageException",
        ):
            return None
        raise
    if resp["failures"] or not resp["images"]:
        return None
    return resp["images"][0]


def _try_start_image_scan(ecr, repo_name: str, image_id: dict):
    try:
        return ecr.start_image_scan(repositoryName=repo_name, imageId=image_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ImageNotFoundException":
            return None
        raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_repository(ctx, repo_name: str) -> None:
    ecr = ctx.client("ecr")
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _safe_delete_ptc_rule(ctx, prefix: str) -> None:
    ecr = ctx.client("ecr")
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ClientError as err:
        if err.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

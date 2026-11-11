"""e2e-pull-through-cache-rule-consumption-flow."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pull-through-cache-rule-consumption-flow"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pull-through cache rule validates and mirrors an upstream image; after the rule is deleted
    it is not found, while the mirrored repository and image digest are unchanged."""
    ecr = ctx.client("ecr")

    prefix = _ecr_prefix(ctx, "ptc")
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, upstreamRegistryUrl="public.ecr.aws"
    )
    repo_name = f"{prefix}/amazonlinux/amazonlinux"
    ctx.on_cleanup(lambda: _safe_delete_repository(ctx, repo_name))

    validation = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    assert validation["isValid"] is True, validation

    image = _poll_until(
        lambda: _try_batch_get_image(ecr, repo_name, "latest"),
        lambda result: result is not None,
        timeout_s=180.0,
        interval_s=5.0,
    )
    digest_before = image["imageId"]["imageDigest"]

    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)

    code, message = _error(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    )
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"describing the deleted rule {prefix!r} returned {code!r}, not the specific "
        f"not-found code"
    )
    expected = f"A pull-through cache rule with repository prefix '{prefix}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = ecr.batch_get_image(
        repositoryName=repo_name, imageIds=[{"imageTag": "latest"}]
    )
    assert not still_there["failures"], (
        f"batch_get_image reported failures for {repo_name} after the cache rule was "
        f"deleted: {still_there['failures']!r}"
    )
    assert still_there["images"][0]["imageId"]["imageDigest"] == digest_before, (
        f"the mirrored image's digest changed from {digest_before!r} to "
        f"{still_there['images'][0]['imageId']['imageDigest']!r} after the cache rule was deleted"
    )
    described = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]
    assert described["repositoryName"] == repo_name, (
        f"describe_repositories returned {described.get('repositoryName')!r} for {repo_name!r} "
        f"after the cache rule was deleted"
    )


def _ecr_prefix(ctx, tag: str) -> str:
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


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_repository(ctx, repo_name: str, timeout_s: float = 60.0) -> None:
    ecr = ctx.client("ecr")
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _repo_gone(ecr, repo_name):
            return
        time.sleep(1.0)
    raise AssertionError(f"repository {repo_name} still present {timeout_s}s after force delete")


def _repo_gone(ecr, repo_name: str) -> bool:
    """True once DescribeRepositories answers RepositoryNotFoundException."""
    try:
        ecr.describe_repositories(repositoryNames=[repo_name])
    except ClientError as err:
        if err.response["Error"]["Code"] == "RepositoryNotFoundException":
            return True
        raise
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

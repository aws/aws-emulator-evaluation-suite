"""registry-id-stable-across-calls."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "registry-id-stable-across-calls"
GROUP = "server-side"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ECR Public is a us-east-1-only API, so the client is pinned through
    `ctx.client(..., region=)`."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The registry identifier returned by DescribeRegistries is stable and identical
    across repeated calls, confirming the single-registry-per-account server-side
    invariant (and that registryId equals the caller's own account id)."""
    ecr = _ecrpub_client(ctx)

    # The registry's alias and registryUri appear on the account's first CreateRepository:
    # create one so the registry is populated by this check, not by prior account state.
    name = ctx.unique_name("sim2real-behav-ecrpub-regid-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    first = ecr.describe_registries()["registries"]
    assert len(first) == 1, f"expected exactly one registry, got {len(first)}"

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    assert first[0]["registryId"] == account_id, (
        f"registryId must equal the caller's account id: "
        f"registryId={first[0]['registryId']!r} account={account_id!r}"
    )

    # Re-sample DescribeRegistries repeatedly across a bounded window rather than
    # sleeping a fixed duration then checking once: every sample in the window must
    # match `first`, and we require at least a couple of samples before concluding.
    samples = _poll_collect(
        lambda: ecr.describe_registries()["registries"],
        min_samples=3,
        timeout_s=10.0,
        interval_s=0.5,
    )
    for sample in samples:
        assert len(sample) == 1, f"expected exactly one registry, got {len(sample)}"
        assert sample[0]["registryId"] == first[0]["registryId"], (
            f"registryId drifted across calls: first={first[0]['registryId']!r} "
            f"sample={sample[0]['registryId']!r}"
        )
        assert sample[0]["registryArn"] == first[0]["registryArn"], (
            f"registryArn drifted across calls: first={first[0]['registryArn']!r} "
            f"sample={sample[0]['registryArn']!r}"
        )
        assert sample[0]["registryUri"] == first[0]["registryUri"], (
            f"registryUri drifted across calls: first={first[0]['registryUri']!r} "
            f"sample={sample[0]['registryUri']!r}"
        )
        assert sample[0]["verified"] == first[0]["verified"], (
            f"verified drifted across calls: first={first[0]['verified']!r} "
            f"sample={sample[0]['verified']!r}"
        )


def _poll_collect(probe, *, min_samples: int, timeout_s: float, interval_s: float):
    """Collect at least `min_samples` probe results, spaced interval_s apart, within a
    bounded timeout window. Raises if the window elapses before enough samples land."""
    samples = []
    deadline = time.monotonic() + timeout_s
    while len(samples) < min_samples and time.monotonic() < deadline:
        samples.append(probe())
        if len(samples) < min_samples:
            time.sleep(interval_s)
    if len(samples) < min_samples:
        raise AssertionError(
            f"only collected {len(samples)}/{min_samples} samples within {timeout_s}s"
        )
    return samples


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""batch-get-repository-scanning-configuration-multi-repo."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "batch-get-repository-scanning-configuration-multi-repo"
GROUP = "server-side"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """BatchGetRepositoryScanningConfiguration returns the correct, independently-set
    per-repository scanOnPush/scanFrequency for multiple repositories in one call."""
    ecr = ctx.client("ecr")

    # The per-repository scanOnPush setting only determines the effective scanFrequency
    # when the registry-wide scanning configuration is BASIC with no (or no matching)
    # rules. If a prior test (or account state) has left the registry with an ENHANCED
    # scan type, or a BASIC rule whose filter matches these repositories, that
    # registry-level configuration takes precedence and per-repo scanOnPush becomes
    # vestigial -- so pin the registry to a known BASIC/no-rules state for the duration
    # of this check and restore whatever was there before on cleanup.
    original_registry_cfg = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    ctx.on_cleanup(
        lambda: ecr.put_registry_scanning_configuration(
            scanType=original_registry_cfg.get("scanType", "BASIC"),
            rules=original_registry_cfg.get("rules", []),
        )
    )
    ecr.put_registry_scanning_configuration(scanType="BASIC", rules=[])

    repo_on = ctx.unique_name("sim2real-behav-scanon-")
    repo_off = ctx.unique_name("sim2real-behav-scanoff-")

    ecr.create_repository(
        repositoryName=repo_on, imageScanningConfiguration={"scanOnPush": True}
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_on, force=True))
    ecr.create_repository(
        repositoryName=repo_off, imageScanningConfiguration={"scanOnPush": False}
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_off, force=True))

    # The scanning configuration derived from imageScanningConfiguration at repository
    # creation time is not guaranteed to be immediately visible via
    # BatchGetRepositoryScanningConfiguration (it is populated slightly asynchronously
    # relative to CreateRepository returning), so poll for it to settle instead of
    # asserting on the very first read.
    def _fetch():
        r = ecr.batch_get_repository_scanning_configuration(
            repositoryNames=[repo_on, repo_off]
        )
        return {
            "failures": r.get("failures", []),
            "configs": {c["repositoryName"]: c for c in r["scanningConfigurations"]},
        }

    def _settled(state) -> bool:
        cfgs = state["configs"]
        return (
            cfgs.get(repo_on, {}).get("scanFrequency") == "SCAN_ON_PUSH"
            and cfgs.get(repo_off, {}).get("scanFrequency") == "MANUAL"
        )

    # Give this extra headroom beyond the base propagation delay: the registry-wide
    # reset performed above also needs to settle before the per-repo scanOnPush values
    # take effect, and that registry-level propagation has been observed to lag more
    # than a plain per-repo-config read would.
    state = _poll_until(_fetch, _settled, timeout_s=90.0, interval_s=3.0)
    assert state["failures"] == [], f"unexpected failures: {state['failures']}"

    configs = state["configs"]
    assert set(configs) == {repo_on, repo_off}, (
        f"expected configs for both {repo_on!r} and {repo_off!r}, got {sorted(configs)}"
    )

    assert configs[repo_on]["scanOnPush"] is True, (
        f"expected scanOnPush=True for {repo_on!r}, got {configs[repo_on]['scanOnPush']!r}"
    )
    assert configs[repo_off]["scanOnPush"] is False, (
        f"expected scanOnPush=False for {repo_off!r}, got {configs[repo_off]['scanOnPush']!r}"
    )
    # Basic scanning: scanOnPush=True repositories scan on every push; False means
    # findings are only produced via a manual StartImageScan call.
    assert configs[repo_on]["scanFrequency"] == "SCAN_ON_PUSH", (
        f"expected scanFrequency=SCAN_ON_PUSH for {repo_on!r}, got "
        f"{configs[repo_on]['scanFrequency']!r}"
    )
    assert configs[repo_off]["scanFrequency"] == "MANUAL", (
        f"expected scanFrequency=MANUAL for {repo_off!r}, got "
        f"{configs[repo_off]['scanFrequency']!r}"
    )
    assert configs[repo_on]["repositoryArn"].endswith(f"repository/{repo_on}"), (
        f"expected repositoryArn ending 'repository/{repo_on}', got "
        f"{configs[repo_on]['repositoryArn']!r}"
    )
    assert configs[repo_off]["repositoryArn"].endswith(f"repository/{repo_off}"), (
        f"expected repositoryArn ending 'repository/{repo_off}', got "
        f"{configs[repo_off]['repositoryArn']!r}"
    )

    # A repository name that doesn't exist is reported as a per-item failure, not a
    # hard error, and does not suppress the results for the repositories that do exist.
    bogus = ctx.unique_name("sim2real-behav-scanmissing-")
    resp2 = ecr.batch_get_repository_scanning_configuration(
        repositoryNames=[repo_on, bogus]
    )
    failures2 = {f["repositoryName"]: f["failureCode"] for f in resp2.get("failures", [])}
    assert failures2.get(bogus) == "REPOSITORY_NOT_FOUND", (
        f"expected failureCode=REPOSITORY_NOT_FOUND for missing repo {bogus!r}, got "
        f"{failures2.get(bogus)!r} (failures: {failures2})"
    )
    ok_names2 = {c["repositoryName"] for c in resp2["scanningConfigurations"]}
    assert ok_names2 == {repo_on}, (
        f"expected only {repo_on!r} in scanningConfigurations alongside the missing "
        f"repo failure, got {sorted(ok_names2)}"
    )


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

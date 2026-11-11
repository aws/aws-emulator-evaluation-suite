"""ordering-upgrade-history-chronological-sequence."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ordering-upgrade-history-chronological-sequence"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One eligibility check (PerformCheckOnly=True) appends one GetUpgradeHistory entry; a second
    against a DIFFERENT target leaves the history unchanged. The model documents one entry per
    eligibility check; real AWS collapses the second into the first, and that is what is graded."""
    aos = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-osup-")
    aos.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_1.3",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: aos.delete_domain(DomainName=domain_name))
    _wait_domain_active(ctx, aos, domain_name)

    targets = _pick_two_compatible_targets(aos, domain_name)
    if targets is None:
        raise AssertionError(
            "domain's compatible-version matrix does not currently offer two "
            "distinct upgrade targets to check eligibility against"
        )
    target_1, target_2 = targets

    history_before_1 = _get_full_history(aos, domain_name)

    _call_retrying_background_tasks(
        lambda: aos.upgrade_domain(DomainName=domain_name, TargetVersion=target_1, PerformCheckOnly=True)
    )
    _wait_upgrade_terminal(ctx, aos, domain_name)
    history_after_1 = _get_full_history(aos, domain_name)
    new_after_1 = _new_entries(history_before_1, history_after_1)
    assert len(new_after_1) == 1, (
        f"expected exactly 1 new GetUpgradeHistory entry after the first eligibility "
        f"check, got {len(new_after_1)}"
    )
    # Re-confirm the domain has settled (Processing=False) before the second check, ruling
    # out "still mid-check" as the explanation for what follows.
    _wait_domain_active(ctx, aos, domain_name)

    _call_retrying_background_tasks(
        lambda: aos.upgrade_domain(DomainName=domain_name, TargetVersion=target_2, PerformCheckOnly=True)
    )
    _wait_upgrade_terminal(ctx, aos, domain_name)
    history_after_2 = _get_full_history(aos, domain_name)
    assert history_after_2 == history_after_1, (
        "a second eligibility check against a different target version changed "
        f"GetUpgradeHistory, contradicting the collapsing behavior observed on real AWS: "
        f"target_1={target_1!r} target_2={target_2!r}; "
        f"before={history_after_1!r} after={history_after_2!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _wait_domain_active(ctx, aos, domain_name: str) -> None:
    def _status():
        return aos.describe_domain(DomainName=domain_name)["DomainStatus"]

    _poll_until(
        _status,
        lambda s: s.get("Created") and not s.get("Processing"),
        timeout_s=1800,
        interval_s=30,
    )


def _pick_two_compatible_targets(aos, domain_name: str):
    resp = aos.get_compatible_versions(DomainName=domain_name)
    for entry in resp.get("CompatibleVersions", []):
        targets = entry.get("TargetVersions", [])
        if len(targets) >= 2:
            return targets[0], targets[1]
    return None


def _wait_upgrade_terminal(ctx, aos, domain_name: str) -> None:
    def _step_status():
        resp = aos.get_upgrade_status(DomainName=domain_name)
        # Immediately after UpgradeDomain, GetUpgradeStatus can answer with no "StepStatus"
        # key at all for a short window, before the async workflow has started -- observed
        # on real AWS. None reads as non-terminal so the poll keeps waiting rather than
        # crashing on a key that is legitimately, if transiently, absent.
        return resp.get("StepStatus")

    status = _poll_until(
        _step_status,
        lambda s: s in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert status in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), f"eligibility check ended in {status}"


def _call_retrying_background_tasks(fn, *, timeout_s=300.0, interval_s=15.0):
    """Retry a call that can transiently fail with a generic (unmodeled) error while the
    domain still has post-creation background tasks running. botocore can't map that error
    to a real shape, so it surfaces as `errorfactory.BaseException` with Code == "BaseException"
    and a message like "Upgrade failed. Domain has background tasks in progress" -- distinct
    from any real ValidationException/ResourceNotFoundException the check might be asserting
    on, so only THIS specific transient case is retried; everything else propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            err = e.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            if err.get("Code") == "BaseException" and "background tasks" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _new_entries(before: list, after: list) -> list:
    before_keys = {(h.get("UpgradeName"), h.get("StartTimestamp")) for h in before}
    return [h for h in after if (h.get("UpgradeName"), h.get("StartTimestamp")) not in before_keys]


def _get_full_history(aos, domain_name: str) -> list:
    history: list = []
    next_token = None
    while True:
        kwargs = {"DomainName": domain_name}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = aos.get_upgrade_history(**kwargs)
        history.extend(resp.get("UpgradeHistories", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return history


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

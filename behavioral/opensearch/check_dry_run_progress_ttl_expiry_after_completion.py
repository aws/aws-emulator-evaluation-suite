"""dry-run-progress-ttl-expiry-after-completion."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "dry-run-progress-ttl-expiry-after-completion"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A completed dry run stays queryable and "succeeded" across spaced rereads, and never
    changes the live domain's InstanceType."""
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx)
    _create_domain(ctx, domain_name)
    _wait_domain_active(ctx, domain_name, timeout_s=_budget_s(ctx, 1800))

    original_config = client.describe_domain_config(DomainName=domain_name)["DomainConfig"]
    original_instance_type = original_config["ClusterConfig"]["Options"]["InstanceType"]
    assert original_instance_type == "t3.small.search", (
        f"expected the domain to still carry its as-created InstanceType "
        f"t3.small.search, got {original_instance_type!r}"
    )

    # A different instance type forces a real blue/green analysis instead of a
    # trivial no-op dry run.
    resp = client.update_domain_config(
        DomainName=domain_name,
        ClusterConfig={"InstanceType": "t3.medium.search", "InstanceCount": 1},
        DryRun=True,
        DryRunMode="Verbose",
    )
    assert "DryRunProgressStatus" in resp, (
        f"expected a trackable DryRunProgressStatus for a Verbose dry run, got {resp!r}"
    )
    dry_run_id = resp["DryRunProgressStatus"]["DryRunId"]

    status = _wait_for_dry_run_terminal(ctx, domain_name, dry_run_id, timeout_s=_budget_s(ctx, 600))
    assert status == "succeeded", f"expected the dry run to succeed, got status {status!r}"

    # The retention window is undocumented and too long to await; spaced rereads catch a
    # record that regresses mid-window.
    for attempt in range(3):
        time.sleep(3)
        reread = client.describe_dry_run_progress(DomainName=domain_name, DryRunId=dry_run_id)
        reread_status = reread["DryRunProgressStatus"]
        assert reread_status["DryRunId"] == dry_run_id, (
            f"reread #{attempt + 1}: expected DryRunId {dry_run_id!r} unchanged, "
            f"got {reread_status['DryRunId']!r}"
        )
        assert reread_status["DryRunStatus"] == "succeeded", (
            f"reread #{attempt + 1}: expected DryRunStatus to remain succeeded, "
            f"got {reread_status['DryRunStatus']!r}"
        )

    # A dry run must never actually apply the change.
    after_config = client.describe_domain_config(DomainName=domain_name)["DomainConfig"]
    after_instance_type = after_config["ClusterConfig"]["Options"]["InstanceType"]
    assert after_instance_type == original_instance_type, (
        f"DryRun must not mutate live config, but InstanceType is now "
        f"{after_instance_type!r} (was {original_instance_type!r})"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _domain_name(ctx: Any) -> str:
    name = ctx.unique_name("sim2real-osdry-").lower()
    return name[:28].rstrip("-")


def _create_domain(ctx, domain_name: str) -> None:
    client = ctx.client("opensearch")
    client.create_domain(
        DomainName=domain_name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup() -> None:
        try:
            client.delete_domain(DomainName=domain_name)
        except client.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)


def _wait_domain_active(ctx, domain_name: str, timeout_s: float) -> None:
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


def _wait_for_dry_run_terminal(ctx, domain_name: str, dry_run_id: str, timeout_s: float) -> str:
    """Poll until the dry run is terminal; AWS uses lowercase 'succeeded'/'failed'."""
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = client.describe_dry_run_progress(DomainName=domain_name, DryRunId=dry_run_id)
        last_status = resp["DryRunProgressStatus"]["DryRunStatus"]
        if last_status in ("succeeded", "failed"):
            return last_status
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"dry run {dry_run_id} to reach a terminal status: the run budget ended first; not graded")
    raise AssertionError(
        f"dry run {dry_run_id} never reached a terminal status within {timeout_s}s "
        f"(last status: {last_status!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

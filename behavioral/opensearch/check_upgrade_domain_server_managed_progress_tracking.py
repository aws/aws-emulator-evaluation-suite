"""upgrade-domain-server-managed-progress-tracking."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "upgrade-domain-server-managed-progress-tracking"
GROUP = "server-side"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpgradeDomain kicks off a service-managed engine upgrade whose progress is
    observable purely via GetUpgradeStatus / GetUpgradeHistory -- no further
    client-driven step calls are required to advance it to a terminal state."""
    client = ctx.client("opensearch")

    pairs = client.get_compatible_versions().get("CompatibleVersions", [])
    chosen = None
    for pair in pairs:
        source = pair.get("SourceVersion", "")
        targets = [t for t in pair.get("TargetVersions", []) if t.startswith("OpenSearch_")]
        if source.startswith("OpenSearch_") and targets:
            chosen = (source, sorted(targets)[0])
            break
    if chosen is None:
        raise AssertionError(
            "no OpenSearch_x.y -> OpenSearch_x.y upgrade path is currently offered by "
            "GetCompatibleVersions in this account/region"
        )
    source_version, target_version = chosen

    domain_name = _create_minimal_domain(ctx, engine_version=source_version)
    _wait_domain_active(ctx, domain_name, timeout_s=1100.0, interval_s=30.0, quiescent_polls=2)

    # Right after a domain finishes provisioning, the service can still report transient
    # background tasks (e.g. final config propagation) that reject an immediate
    # UpgradeDomain call; retry with backoff until that clears or the budget runs out.
    upgrade_deadline = time.monotonic() + 180.0
    while True:
        try:
            client.upgrade_domain(DomainName=domain_name, TargetVersion=target_version)
            break
        except ClientError as err:
            msg = str(err)
            if "background tasks in progress" not in msg or time.monotonic() >= upgrade_deadline:
                raise
            time.sleep(2)

    # Only GetUpgradeStatus is polled -- no client-driven step call -- until the UPGRADE step
    # reaches a terminal status, bounded by the check's remaining budget.
    cap = 2400.0
    deadline = time.monotonic() + min(cap, (ctx.time_left() or cap) - 200)
    observed_status = None
    while time.monotonic() < deadline:
        observed_status = client.get_upgrade_status(DomainName=domain_name)
        if observed_status.get("UpgradeStep") == "UPGRADE" and observed_status.get("StepStatus") in (
            "SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"
        ):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"upgrade never reached a terminal UPGRADE step; last GetUpgradeStatus {observed_status!r}")
    assert observed_status["StepStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), (
        f"upgrade to {target_version} ended in StepStatus {observed_status['StepStatus']!r}: {observed_status!r}"
    )
    assert observed_status.get("UpgradeName"), f"GetUpgradeStatus did not name the upgrade: {observed_status!r}"

    # GetUpgradeHistory can lag GetUpgradeStatus briefly; poll the newest entry to its terminal status.
    history_deadline = time.monotonic() + min(180.0, (ctx.time_left() or 180.0) - 5)
    latest = None
    while time.monotonic() < history_deadline:
        history = client.get_upgrade_history(DomainName=domain_name)["UpgradeHistories"]
        latest = max(history, key=lambda h: h.get("StartTimestamp", 0)) if history else None
        if latest and latest["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"):
            break
        time.sleep(2)
    assert latest is not None, "GetUpgradeHistory has no record of the upgrade"
    assert latest["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), (
        f"latest GetUpgradeHistory entry status is {latest['UpgradeStatus']!r}: {latest!r}"
    )
    assert len(latest.get("StepsList", [])) >= 1, f"upgrade history entry recorded no steps: {latest!r}"

    engine_version = client.describe_domain(DomainName=domain_name)["DomainStatus"]["EngineVersion"]
    assert engine_version == target_version, (
        f"EngineVersion {engine_version!r} after the upgrade, expected {target_version!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _domain_access_policy(ctx, domain_name: str) -> str:
    account_id = _account_id(ctx)
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "es:*",
                    "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
                }
            ],
        }
    )


def _create_minimal_domain(ctx, engine_version: str | None = None, auto_tune_enabled: bool = False) -> str:
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-ost-")
    kwargs = {
        "DomainName": name,
        "ClusterConfig": {"InstanceType": "t3.small.search", "InstanceCount": 1},
        "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        "AccessPolicies": _domain_access_policy(ctx, name),
        # Tagged at creation so a tag-based cleanup can find this domain if teardown is interrupted.
        "TagList": [{"Key": "sim2real", "Value": "upgrade-domain-server-managed-progress-tracking"}],
    }
    if engine_version:
        kwargs["EngineVersion"] = engine_version
    if auto_tune_enabled:
        kwargs["AutoTuneOptions"] = {"DesiredState": "ENABLED"}
    client.create_domain(**kwargs)
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return name


def _wait_domain_active(
    ctx, domain_name: str, timeout_s: float = 1800.0, interval_s: float = 30.0, quiescent_polls: int = 1
) -> dict:
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    consecutive = 0
    status = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if not status.get("Processing", True):
            consecutive += 1
            if consecutive >= quiescent_polls:
                return status
        else:
            consecutive = 0
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not reach an idle (Processing=False) state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

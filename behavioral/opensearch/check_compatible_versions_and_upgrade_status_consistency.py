"""compatible-versions-and-upgrade-status-consistency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compatible-versions-and-upgrade-status-consistency"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Only versions returned by GetCompatibleVersions/ListVersions can be reached
    by an UpgradeDomain call, and GetUpgradeStatus/GetUpgradeHistory reflect the
    completed target version once the upgrade finishes."""
    aos = ctx.client("opensearch")

    picked_version = _pick_older_opensearch_version(ctx, back_from_latest=2)
    if not picked_version:
        raise AssertionError("could not determine an older OpenSearch engine version to seed the test domain")

    try:
        name = _create_minimal_domain(ctx, engine_version=picked_version)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationException":
            raise AssertionError(f"engine version {picked_version!r} unavailable for new domain creation")
        raise

    _wait_domain_active(ctx, name, timeout_s=2400.0)

    all_versions: set[str] = set()
    resp = aos.list_versions(MaxResults=100)
    all_versions.update(resp.get("Versions", []))
    while resp.get("NextToken"):
        resp = aos.list_versions(MaxResults=100, NextToken=resp["NextToken"])
        all_versions.update(resp.get("Versions", []))
    assert picked_version in all_versions, "the version the domain was created with is not in ListVersions"

    compatible = aos.get_compatible_versions(DomainName=name)["CompatibleVersions"]
    entry = next((c for c in compatible if c["SourceVersion"] == picked_version), None)
    targets = entry.get("TargetVersions", []) if entry else []
    if not targets:
        raise AssertionError(f"no compatible upgrade target advertised for {picked_version!r}")
    # Pick the CLOSEST compatible target (smallest version hop) rather than the furthest one:
    # a real UpgradeDomain blue/green deployment's wall-clock duration is not bounded by this
    # check's own poll timeouts but by the harness's overall run budget, so minimizing the
    # version distance (while still exercising a genuine upgrade) is what keeps this check
    # completing in time on real AWS.
    target_version = min(targets, key=_version_sort_key)
    assert target_version in all_versions, "GetCompatibleVersions returned a version absent from ListVersions"

    # Immediately after a domain reaches Created&&!Processing, UpgradeDomain can still
    # reject with a generic (unmodeled -> botocore "BaseException") "Domain has background
    # tasks in progress" error for a little while longer -- the Active transition doesn't
    # strictly mean every post-creation background task has settled. Retry past that
    # transient window instead of treating it as fatal.
    upgrade_resp = _call_retrying_background_tasks(
        lambda: aos.upgrade_domain(DomainName=name, TargetVersion=target_version)
    )
    assert upgrade_resp["TargetVersion"] == target_version

    final_status = _poll_until(
        lambda: aos.get_upgrade_status(DomainName=name),
        lambda s: s.get("StepStatus") in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"),
        timeout_s=2400.0,
        interval_s=20.0,
    )
    assert final_status["StepStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), final_status

    # GetUpgradeHistory can lag slightly behind GetUpgradeStatus -- the latest history
    # entry may still read "IN_PROGRESS" for a short window after GetUpgradeStatus has
    # already reported a terminal StepStatus. Poll it instead of taking a single snapshot.
    def _latest_history_entry():
        history = aos.get_upgrade_history(DomainName=name)["UpgradeHistories"]
        assert history, "GetUpgradeHistory returned no entries after a completed upgrade"
        return max(history, key=lambda h: h.get("StartTimestamp", 0))

    latest = _poll_until(
        _latest_history_entry,
        lambda h: h["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"),
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert latest["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), latest

    final_domain = aos.describe_domain(DomainName=name)["DomainStatus"]
    assert final_domain["EngineVersion"] == target_version, (
        "domain engine version does not reflect the completed upgrade target"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _version_sort_key(v):
    try:
        major, minor = v.split("_", 1)[1].split(".")
        return (int(major), int(minor))
    except Exception:
        return (0, 0)


def _pick_older_opensearch_version(ctx, back_from_latest=2):
    aos = ctx.client("opensearch")
    versions: list[str] = []
    resp = aos.list_versions(MaxResults=100)
    versions.extend(resp.get("Versions", []))
    while resp.get("NextToken"):
        resp = aos.list_versions(MaxResults=100, NextToken=resp["NextToken"])
        versions.extend(resp.get("Versions", []))

    def key(v):
        try:
            major, minor = v.split("_", 1)[1].split(".")
            return (int(major), int(minor))
        except Exception:
            return (0, 0)

    os_versions = sorted((v for v in versions if v.startswith("OpenSearch_")), key=key)
    if len(os_versions) < 2:
        return None
    # OpenSearch_2.13 has been observed to provision noticeably faster than whatever the
    # account's current default/latest engine is -- domain creation alone can otherwise eat
    # most of the harness's wall-clock budget before the upgrade even starts. Prefer it when
    # it's available and isn't already the newest engine (so a forward upgrade target exists).
    if "OpenSearch_2.13" in os_versions and os_versions.index("OpenSearch_2.13") < len(os_versions) - 1:
        return "OpenSearch_2.13"
    idx = max(0, len(os_versions) - 1 - back_from_latest)
    return os_versions[idx]


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


def _create_minimal_domain(ctx, engine_version=None):
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-osb2-")
    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
        }],
    })
    kwargs = dict(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
    )
    if engine_version:
        kwargs["EngineVersion"] = engine_version
    aos.create_domain(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name


def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s=2400.0):
    aos = ctx.client("opensearch")

    def probe():
        return aos.describe_domain(DomainName=name)["DomainStatus"]

    def done(s):
        return bool(s.get("Created")) and not s.get("Processing")

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=20.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

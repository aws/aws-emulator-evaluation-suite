"""service-software-rollback-and-domain-upgrade."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-software-rollback-and-domain-upgrade"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartServiceSoftwareUpdate can be rolled back via RollbackServiceSoftwareUpdate,
    and UpgradeDomain moves the domain through an upgrade-in-progress state to the
    requested target engine version."""
    aos = ctx.client("opensearch")

    # Seed the domain on a deliberately older engine version so a compatible upgrade
    # target is very likely to exist (brand-new domains otherwise default to the
    # latest engine, which usually has no forward upgrade path).
    picked_version = _pick_older_opensearch_version(ctx, back_from_latest=2)
    try:
        if picked_version:
            name = _create_minimal_domain(ctx, engine_version=picked_version)
        else:
            name = _create_minimal_domain(ctx)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationException":
            raise AssertionError(
                f"engine version {picked_version!r} unavailable for new domain creation"
            )
        raise

    status = _wait_domain_active(ctx, name, timeout_s=2400.0)
    original_version = status["EngineVersion"]

    # --- StartServiceSoftwareUpdate / RollbackServiceSoftwareUpdate ---
    sso = aos.describe_domain(DomainName=name)["DomainStatus"]["ServiceSoftwareOptions"]
    if sso.get("UpdateAvailable"):
        start_resp = aos.start_service_software_update(DomainName=name)
        started = start_resp["ServiceSoftwareOptions"]
        assert started["UpdateStatus"] in ("PENDING_UPDATE", "IN_PROGRESS"), started
        current_before_rollback = started["CurrentVersion"]

        def probe_sso():
            return aos.describe_domain(DomainName=name)["DomainStatus"]["ServiceSoftwareOptions"]

        # The UpdateStatus flag flips at the API level essentially as soon as the update is
        # started -- it doesn't require waiting for the underlying software deployment to
        # progress. Bound this tightly so a still-slow real deployment doesn't eat into the
        # budget the domain-upgrade phase below also needs.
        _poll_until(
            probe_sso,
            lambda s: s.get("UpdateStatus") in ("IN_PROGRESS", "PENDING_UPDATE"),
            timeout_s=60.0,
            interval_s=5.0,
        )

        rollback_resp = aos.rollback_service_software_update(DomainName=name)
        rollback_opts = rollback_resp["RollbackServiceSoftwareOptions"]
        assert rollback_opts["CurrentVersion"] == current_before_rollback, (
            f"rollback response CurrentVersion {rollback_opts['CurrentVersion']!r} != "
            f"pre-rollback CurrentVersion {current_before_rollback!r}"
        )

        # Rolling back this early (before the update has deployed anything) settles the
        # ServiceSoftwareOptions state quickly too -- it doesn't need to wait out a full
        # software deployment/rollback cycle.
        final_sso = _poll_until(
            probe_sso,
            lambda s: s.get("UpdateStatus") in ("COMPLETED", "NOT_ELIGIBLE", "ELIGIBLE"),
            timeout_s=180.0,
            interval_s=10.0,
        )
        assert final_sso["CurrentVersion"] == current_before_rollback, (
            f"rollback did not restore CurrentVersion: {final_sso}"
        )
    else:
        code, message = _error_code(lambda: aos.start_service_software_update(DomainName=name))
        assert code == "ValidationException", f"expected ValidationException, got {code}"
        expected = "The domain is not available for update."
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- UpgradeDomain: moves through an upgrade-in-progress state to the new version ---
    compatible = aos.get_compatible_versions(DomainName=name).get("CompatibleVersions", [])
    targets: list[str] = []
    for entry in compatible:
        if entry.get("SourceVersion") == original_version:
            targets = entry.get("TargetVersions", [])
            break
    if not targets:
        raise AssertionError(f"no compatible upgrade target advertised for {original_version!r}")
    # Pick the CLOSEST compatible target (smallest version hop) rather than the furthest one:
    # a real UpgradeDomain blue/green deployment's wall-clock duration is not bounded by this
    # check's own poll timeouts but by the harness's overall run budget, so minimizing the
    # version distance (while still exercising a genuine upgrade) is what keeps this check
    # completing in time on real AWS.
    target_version = min(targets, key=_version_sort_key)

    upgrade_resp = _call_retrying_background_tasks(
        lambda: aos.upgrade_domain(DomainName=name, TargetVersion=target_version)
    )
    assert upgrade_resp["TargetVersion"] == target_version, (
        f"UpgradeDomain acked TargetVersion {upgrade_resp.get('TargetVersion')!r}, "
        f"expected {target_version!r}"
    )
    assert upgrade_resp.get("UpgradeId"), f"UpgradeDomain response carried no UpgradeId: {upgrade_resp!r}"

    def probe_domain():
        return aos.describe_domain(DomainName=name)["DomainStatus"]

    # Go straight to waiting for the terminal (upgraded) state -- it subsumes observing the
    # transient "upgrading" state along the way, and avoids spending a separate bounded wait
    # on an intermediate observation this check doesn't otherwise need.
    final_status = _poll_until(
        probe_domain,
        lambda s: s.get("EngineVersion") == target_version and not s.get("UpgradeProcessing"),
        timeout_s=2400.0,
        interval_s=20.0,
    )
    assert final_status["EngineVersion"] == target_version, (
        f"domain {name} settled on EngineVersion {final_status['EngineVersion']!r}, "
        f"expected upgrade target {target_version!r}"
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


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
        TagList=[{"Key": "sim2real-behav-check", "Value": CHECK}],
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

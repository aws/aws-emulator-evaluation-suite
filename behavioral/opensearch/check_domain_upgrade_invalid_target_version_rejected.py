"""domain-upgrade-invalid-target-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-upgrade-invalid-target-version-rejected"
GROUP = "deploy"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpgradeDomain rejects a downgrade TargetVersion with BaseException "not supported" and keeps
    EngineVersion, while a forward PerformCheckOnly upgrade succeeds and appears in upgrade history.
    """
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    domain_name = ctx.unique_name("sim2real-upg-")[:28].rstrip("-") or "sim2real-upg-fallback"
    policy = {
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
    create_resp = osc.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
    )
    ctx.on_cleanup(lambda: _delete_domain_quiet(osc, domain_name))
    osc.add_tags(
        ARN=create_resp["DomainStatus"]["ARN"],
        TagList=[{"Key": "sim2real", "Value": "domain-upgrade-invalid-target-version-rejected"}],
    )
    domain_status = _wait_domain_active(osc, domain_name, timeout_s=2400.0)
    original_engine_version = domain_status["EngineVersion"]

    # --- negative: a downgrade target is not a valid upgrade path (unmodeled BaseException) ---
    code, message = _error_retrying_background_tasks(
        lambda: osc.upgrade_domain(
            DomainName=domain_name, TargetVersion="OpenSearch_1.0", PerformCheckOnly=True
        )
    )
    assert code == "BaseException", (
        f"expected UpgradeDomain to reject a downgrade TargetVersion with BaseException, "
        f"got {code!r}"
    )
    expected_message = (
        f"Failed to submit upgrade. Upgrade from {original_engine_version} to OpenSearch_1.0 "
        f"not supported."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the effect is absent: the domain's engine version is unchanged, read independently
    unchanged = osc.describe_domain(DomainName=domain_name)["DomainStatus"]["EngineVersion"]
    assert unchanged == original_engine_version, (
        f"expected EngineVersion to remain {original_engine_version!r} after a rejected "
        f"downgrade, got {unchanged!r}"
    )

    # --- positive control: a real forward-compatible target still passes the check ---
    compat = osc.get_compatible_versions(DomainName=domain_name)["CompatibleVersions"]
    entry = next((c for c in compat if c["SourceVersion"] == original_engine_version), None)
    assert entry is not None and entry["TargetVersions"], (
        f"expected GetCompatibleVersions to advertise a forward target from "
        f"{original_engine_version!r}, got {compat!r}"
    )
    valid_target = entry["TargetVersions"][0]

    upgrade_resp = _retry_on_background_tasks(
        lambda: osc.upgrade_domain(
            DomainName=domain_name, TargetVersion=valid_target, PerformCheckOnly=True
        )
    )
    assert upgrade_resp["TargetVersion"] == valid_target, (
        f"expected the check-only call to echo TargetVersion={valid_target!r}, got "
        f"{upgrade_resp.get('TargetVersion')!r}"
    )

    # independent read at the destination: the check-only run must settle to a terminal
    # StepStatus and be recorded in GetUpgradeHistory -- not just the mutating call's own response.
    final_status = _poll_until(
        lambda: osc.get_upgrade_status(DomainName=domain_name),
        lambda s: s.get("StepStatus") in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
        description="upgrade-eligibility check-only run settling to a terminal StepStatus",
    )
    assert final_status["StepStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), (
        f"expected the compatible-target check-only call to succeed, got status {final_status!r}"
    )

    def _latest_history_entry():
        history = osc.get_upgrade_history(DomainName=domain_name)["UpgradeHistories"]
        assert history, "GetUpgradeHistory returned no entries after a completed check-only run"
        return max(history, key=lambda h: h.get("StartTimestamp", 0))

    latest = _poll_until(
        _latest_history_entry,
        lambda h: h["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"),
        timeout_s=180.0,
        interval_s=10.0,
        description="GetUpgradeHistory catching up with the completed check-only run",
    )
    assert latest["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), (
        f"expected the latest GetUpgradeHistory entry to be terminal-successful, got {latest!r}"
    )


def _error_retrying_background_tasks(fn, *, timeout_s=300.0, interval_s=15.0):
    """Call fn(); return its botocore (code, message); an unexpected success raises.

    A transient BaseException "background tasks in progress" (domain not yet settled) is retried.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            if err.get("Code") == "BaseException" and "background tasks" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _retry_on_background_tasks(fn, *, timeout_s=300.0, interval_s=15.0):
    """Retry a call expected to succeed past a transient "background tasks in progress" error."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            if err.get("Code") == "BaseException" and "background tasks" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _wait_domain_active(osc, domain_name, timeout_s=2400.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last["Processing"] is False:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became Active within {timeout_s}s: {last}")


def _delete_domain_quiet(osc, domain_name):
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

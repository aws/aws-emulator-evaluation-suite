"""domain-upgrade-lifecycle."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-upgrade-lifecycle"
GROUP = 'domain'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _create_domain(ctx, osc, domain_name, *, engine_version=ENGINE_VERSION) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=engine_version,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
    )
    for _attempt in range(12):
        if _attempt == 0:
            # Stagger concurrent runs against the account's concurrent-domain-creation limit.
            time.sleep(random.uniform(0, 20.0))
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    osc.add_tags(
        ARN=resp["DomainStatus"]["ARN"],
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    return resp["DomainStatus"]


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Bounded poll until Processing=False and Created=True; the same budget applies on
    every target, and a domain that never settles raises."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name} never became Active within {budget}s",
    )


def _retry_on(fn, *, error_codes=(), message_substrings=(), attempts=6, delay_s=10.0):
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if attempt < attempts - 1 and (
                code in error_codes or any(s in msg for s in message_substrings)
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _error(fn) -> "tuple[str, str]":
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCompatibleVersions lists targets for the domain; a check-only UpgradeDomain reaches a SUCCEEDED step
    status and appears in GetUpgradeHistory; a downgrade fails with BaseException and its exact message and
    leaves EngineVersion unchanged.
    """
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain, engine_version="OpenSearch_2.11")
    _wait_domain_active(ctx, osc, domain)

    compatible = osc.get_compatible_versions(DomainName=domain)["CompatibleVersions"]
    entry = next((c for c in compatible if c["SourceVersion"] == "OpenSearch_2.11"), None)
    assert entry is not None and entry["TargetVersions"], (
        f"expected at least one upgrade target from OpenSearch_2.11, got {compatible}"
    )
    target = entry["TargetVersions"][0]

    upgrade_resp = _retry_on(
        lambda: osc.upgrade_domain(
            DomainName=domain, TargetVersion=target, PerformCheckOnly=True
        ),
        error_codes=("BaseException",),
        message_substrings=("background tasks",),
        attempts=10,
        delay_s=20.0,
    )
    assert upgrade_resp["TargetVersion"] == target, (
        f"expected UpgradeDomain to echo TargetVersion={target!r}, got {upgrade_resp!r}"
    )
    assert upgrade_resp["DomainName"] == domain, (
        f"expected UpgradeDomain to echo DomainName={domain!r}, got {upgrade_resp!r}"
    )

    settled = None
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        settled = osc.get_upgrade_status(DomainName=domain)
        if settled.get("StepStatus") in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"upgrade status not terminal within 600s. Last: {settled!r}")
    assert settled["StepStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), (
        f"expected the compatible-target check-only run to succeed, got {settled!r}"
    )

    def _latest_history_entry():
        entries = osc.get_upgrade_history(DomainName=domain)["UpgradeHistories"]
        assert entries, "GetUpgradeHistory returned no entries after a completed check-only run"
        return max(entries, key=lambda h: h.get("StartTimestamp", 0))

    latest = None
    history_deadline = time.monotonic() + 180
    while time.monotonic() < history_deadline:
        latest = _latest_history_entry()
        if latest["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES", "FAILED"):
            break
        time.sleep(5.0)
    else:
        raise AssertionError(f"GetUpgradeHistory never settled within 180s. Last: {latest!r}")
    assert latest["UpgradeStatus"] in ("SUCCEEDED", "SUCCEEDED_WITH_ISSUES"), (
        f"expected the latest GetUpgradeHistory entry to be terminal-successful, got {latest!r}"
    )

    # Overly-permissive boundary: a downgrade to an Elasticsearch-era version is
    # not a valid upgrade path and must be rejected (real AWS answers with the
    # unmodeled BaseException and an exact "not supported" message).
    code, message = _error(
        lambda: osc.upgrade_domain(
            DomainName=domain, TargetVersion="Elasticsearch_7.10", PerformCheckOnly=True
        )
    )
    assert code == "BaseException", f"expected BaseException, got {code}"
    expected_message = "Failed to submit upgrade. Upgrade from OpenSearch_2.11 to 7.10 not supported."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the effect is absent: the domain's engine version is unchanged, read independently
    unchanged = osc.describe_domain(DomainName=domain)["DomainStatus"]["EngineVersion"]
    assert unchanged == ENGINE_VERSION, (
        f"expected EngineVersion to remain {ENGINE_VERSION!r} after a rejected downgrade, got {unchanged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

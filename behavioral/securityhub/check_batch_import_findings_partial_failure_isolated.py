"""batch-import-findings-partial-failure-isolated."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "batch-import-findings-partial-failure-isolated"
GROUP = "error-semantics"
SERVICES = ["securityhub"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """One invalid finding in a BatchImportFindings batch fails in isolation; the valid sibling still lands."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)

    good_id = ctx.unique_name("sim2real-good-")
    bad_id = ctx.unique_name("sim2real-bad-")
    good = _make_finding(account_id, product_arn, good_id, ctx.unique_name("sim2real-title-"))
    bad = _make_finding(account_id, product_arn, bad_id, ctx.unique_name("sim2real-title-"))
    del bad["Severity"]  # neither Label nor Normalized populated -> the finding is invalid

    resp = sh.batch_import_findings(Findings=[good, bad])
    identifier = {"Id": good_id, "ProductArn": product_arn}
    ctx.on_cleanup(lambda: sh.batch_update_findings(FindingIdentifiers=[identifier], Workflow={"Status": "RESOLVED"}))

    assert resp["SuccessCount"] == 1, f"expected 1 success, got {resp}"
    assert resp["FailedCount"] == 1, f"expected 1 failure, got {resp}"
    failed = resp["FailedFindings"]
    assert len(failed) == 1, f"expected exactly 1 failed finding, got {failed}"
    assert failed[0]["Id"] == bad_id, f"expected failure on {bad_id}, got {failed[0]}"
    assert failed[0].get("ErrorCode") == "InvalidInput", f"expected ErrorCode InvalidInput, got {failed[0]}"
    expected = (
        f"Finding does not adhere to Amazon Finding Format. FindingId: {bad_id} Error: "
        "data should have required property 'Severity', "
        "data should have required property 'FindingProviderFields', "
        "data should match some schema in anyOf."
    )
    assert failed[0].get("ErrorMessage") == expected, (
        f"expected ErrorMessage {expected!r}, got {failed[0].get('ErrorMessage')!r}"
    )

    # Positive control: the good finding landed and is retrievable.
    good_findings = _poll_until(
        lambda: sh.get_findings(Filters={"Id": [{"Value": good_id, "Comparison": "EQUALS"}]})["Findings"],
        lambda fs: len(fs) == 1,
        timeout_s=180,
        interval_s=5,
    )
    assert good_findings[0]["Title"] == good["Title"], (
        f"expected title {good['Title']!r}, got {good_findings[0]['Title']!r}"
    )

    # Effect absent: the invalid finding never landed.
    bad_findings = sh.get_findings(Filters={"Id": [{"Value": bad_id, "Comparison": "EQUALS"}]})["Findings"]
    assert bad_findings == [], f"expected no findings for rejected id {bad_id}, got {bad_findings}"


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _default_product_arn(ctx, account_id):
    return f"arn:aws:securityhub:{ctx.region}:{account_id}:product/{account_id}/default"


def _now_iso():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _make_finding(account_id, product_arn, finding_id, title, severity_label="LOW", **overrides):
    now = _now_iso()
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": product_arn,
        "GeneratorId": "sim2real-behavioral-test",
        "AwsAccountId": account_id,
        "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Title": title,
        "Description": "sim2real behavioral fidelity test finding",
        "Severity": {"Label": severity_label},
        "Resources": [{"Type": "Other", "Id": f"sim2real:{finding_id}"}],
    }
    finding.update(overrides)
    return finding


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


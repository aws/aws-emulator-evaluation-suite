"""batch-import-findings-round-trip."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "batch-import-findings-round-trip"
GROUP = "data-plane"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """A finding submitted via BatchImportFindings is retrievable via GetFindings with matching fields."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)
    finding_id = ctx.unique_name("sim2real-finding-")
    title = ctx.unique_name("sim2real-title-")
    finding = _make_finding(account_id, product_arn, finding_id, title)

    resp = sh.batch_import_findings(Findings=[finding])
    assert resp["FailedCount"] == 0, f"expected FailedCount=0, got {resp['FailedCount']}: {resp.get('FailedFindings')}"
    assert resp["SuccessCount"] == 1, f"expected SuccessCount=1, got {resp['SuccessCount']}"

    identifier = {"Id": finding_id, "ProductArn": product_arn}
    ctx.on_cleanup(lambda: sh.batch_update_findings(FindingIdentifiers=[identifier], Workflow={"Status": "RESOLVED"}))

    findings = _poll_until(
        lambda: sh.get_findings(Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]})["Findings"],
        lambda fs: len(fs) == 1,
        timeout_s=300,
        interval_s=5,
    )
    found = findings[0]
    assert found["Title"] == title, f"expected Title={title!r}, got {found['Title']!r}"
    assert found["Severity"]["Label"] == "LOW", f"expected Severity.Label=LOW, got {found['Severity']['Label']!r}"
    assert found["RecordState"] == "ACTIVE", f"expected RecordState=ACTIVE for a new finding, got {found['RecordState']!r}"
    assert found["Workflow"]["Status"] == "NEW", f"expected Workflow.Status=NEW for a new finding, got {found['Workflow']['Status']!r}"
    assert found["Resources"][0]["Id"] == f"sim2real:{finding_id}", f"expected Resources[0].Id=sim2real:{finding_id}, got {found['Resources'][0]['Id']!r}"


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


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
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

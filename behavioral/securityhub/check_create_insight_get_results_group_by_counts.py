"""create-insight-get-results-group-by-counts."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "create-insight-get-results-group-by-counts"
GROUP = "data-plane"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """A custom insight grouped by SeverityLabel reports counts that match the imported findings."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(ctx, sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)
    generator_id = ctx.unique_name("sim2real-gen-")

    severities = ["LOW", "LOW", "HIGH"]
    ids = []
    for i, sev in enumerate(severities):
        fid = ctx.unique_name(f"sim2real-insight-{i}-")
        ids.append(fid)
        finding = _make_finding(
            account_id, product_arn, fid, ctx.unique_name("sim2real-title-"), severity_label=sev,
            GeneratorId=generator_id,
        )
        resp = _import_with_retry(sh, finding)
        assert resp["FailedCount"] == 0, f"expected FailedCount=0 importing {fid}, got {resp}"

    identifiers = [{"Id": fid, "ProductArn": product_arn} for fid in ids]
    ctx.on_cleanup(lambda: sh.batch_update_findings(FindingIdentifiers=identifiers, Workflow={"Status": "RESOLVED"}))

    for fid in ids:
        _poll_until(
            lambda fid=fid: sh.get_findings(Filters={"Id": [{"Value": fid, "Comparison": "EQUALS"}]})["Findings"],
            lambda fs: len(fs) == 1,
        )

    insight_arn = sh.create_insight(
        Name=ctx.unique_name("sim2real-insight-"),
        Filters={"GeneratorId": [{"Value": generator_id, "Comparison": "EQUALS"}]},
        GroupByAttribute="SeverityLabel",
    )["InsightArn"]
    ctx.on_cleanup(lambda: sh.delete_insight(InsightArn=insight_arn))

    def _counts():
        values = sh.get_insight_results(InsightArn=insight_arn)["InsightResults"]["ResultValues"]
        return {v["GroupByAttributeValue"]: int(v["Count"]) for v in values}

    counts = _poll_until(_counts, lambda c: c.get("LOW") == 2 and c.get("HIGH") == 1, timeout_s=90, interval_s=5)
    assert counts["LOW"] == 2, f"expected LOW=2, got {counts}"
    assert counts["HIGH"] == 1, f"expected HIGH=1, got {counts}"
    assert sum(counts.values()) == len(ids), (
        f"expected the grouped counts to sum to exactly the {len(ids)} findings this check "
        f"imported (no extra or missing group), got {counts}"
    )


def _ensure_hub_enabled(ctx, sh):
    """Enable Security Hub for this check. When this call is what turned the hub on, cleanup
    turns it back off, so the account's hub subscription ends in the state it started in."""
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise
        return
    ctx.on_cleanup(sh.disable_security_hub)


def _import_with_retry(sh, finding, *, timeout_s=60.0, interval_s=5.0):
    """BatchImportFindings against the default product ARN can hit a transient
    AccessDeniedException (resource-policy propagation) for a few seconds right after
    enable_security_hub first activates the hub in a fresh account; retry until that
    clears rather than treating it as a real rejection."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sh.batch_import_findings(Findings=[finding])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


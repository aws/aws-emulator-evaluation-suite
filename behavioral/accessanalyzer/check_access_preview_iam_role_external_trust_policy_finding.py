"""access-preview-iam-role-external-trust-policy-finding."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "access-preview-iam-role-external-trust-policy-finding"
GROUP = "data-plane"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """A proposed IAM role trust policy that trusts a foreign AWS account produces a
    COMPLETED access preview with a non-public external-access finding naming that
    foreign account as principal."""
    aa = ctx.client("accessanalyzer")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    foreign_account = "111111111111" if account_id != "111111111111" else "222222222222"

    analyzer_name = ctx.unique_name("sim2real-aa-preview-role-")
    analyzer_arn = aa.create_analyzer(
        analyzerName=analyzer_name, type="ACCOUNT", tags={"sim2real": CHECK}
    )["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=analyzer_name))
    _poll_analyzer_status(ctx, analyzer_name)

    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-aa-role-')}"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{foreign_account}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    preview_id = aa.create_access_preview(
        analyzerArn=analyzer_arn,
        configurations={role_arn: {"iamRole": {"trustPolicy": json.dumps(trust_policy)}}},
    )["id"]

    status = _poll_preview_status(ctx, analyzer_arn, preview_id)
    assert status == "COMPLETED", f"access preview ended in status={status}"

    findings = aa.list_access_preview_findings(accessPreviewId=preview_id, analyzerArn=analyzer_arn)["findings"]
    role_findings = [f for f in findings if f["resourceType"] == "AWS::IAM::Role"]
    assert role_findings, f"expected an external-access finding for the trusted foreign account, got {findings}"
    finding = role_findings[0]
    assert finding["isPublic"] is False, finding
    assert any(foreign_account in v for v in finding.get("principal", {}).values()), finding.get("principal")


def _poll_analyzer_status(ctx, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    return status


def _poll_preview_status(ctx, analyzer_arn: str, preview_id: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_access_preview(accessPreviewId=preview_id, analyzerArn=analyzer_arn)["accessPreview"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

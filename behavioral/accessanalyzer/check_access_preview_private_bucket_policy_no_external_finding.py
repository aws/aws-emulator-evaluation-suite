"""access-preview-private-bucket-policy-no-external-finding."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "access-preview-private-bucket-policy-no-external-finding"
GROUP = "data-plane"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """A proposed S3 bucket policy granting access only to the analyzer's own account yields a
    COMPLETED access preview with no external-access finding, while a twin preview of a public policy
    on the same analyzer yields one, so an always-empty findings list cannot pass."""
    aa = ctx.client("accessanalyzer")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    analyzer_name = ctx.unique_name("sim2real-aa-preview-priv-")
    analyzer_arn = aa.create_analyzer(
        analyzerName=analyzer_name, type="ACCOUNT", tags={"sim2real-check": CHECK}
    )["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=analyzer_name))
    _poll_analyzer_status(ctx, analyzer_name)

    control_bucket_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-aa-control-pub-bucket-')}"
    control_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadControl",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"{control_bucket_arn}/*",
        }],
    }
    private_bucket_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-aa-priv-bucket-')}"
    private_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "SameAccountOnly",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "s3:GetObject",
            "Resource": f"{private_bucket_arn}/*",
        }],
    }

    # Both previews are started before either is polled, so they run concurrently on the
    # service side rather than one being a stale rehearsal of the other.
    control_preview_id = aa.create_access_preview(
        analyzerArn=analyzer_arn,
        configurations={
            control_bucket_arn: {
                "s3Bucket": {
                    "bucketPolicy": json.dumps(control_policy),
                    # New-bucket default for BPA is "false"; pin it explicitly so the
                    # public grant in the control policy isn't masked by an ambiguous default.
                    "bucketPublicAccessBlock": {
                        "ignorePublicAcls": False,
                        "restrictPublicBuckets": False,
                    },
                }
            },
        },
    )["id"]
    private_preview_id = aa.create_access_preview(
        analyzerArn=analyzer_arn,
        configurations={private_bucket_arn: {"s3Bucket": {"bucketPolicy": json.dumps(private_policy)}}},
    )["id"]

    control_status = _poll_preview_status(ctx, analyzer_arn, control_preview_id)
    assert control_status == "COMPLETED", f"control access preview ended in status={control_status}"
    private_status = _poll_preview_status(ctx, analyzer_arn, private_preview_id)
    assert private_status == "COMPLETED", f"access preview ended in status={private_status}"

    # Finding materialization can lag a beat behind the preview's own COMPLETED status, so poll
    # until the control's public finding lands — that is the positive control, proving the
    # delivery path works at all. By the time it lands, the private preview (started first) has
    # had at least as long to materialize a finding of its own, which the next read bounds.
    control_findings: list = []
    all_control_findings: list = []
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        all_control_findings = aa.list_access_preview_findings(
            accessPreviewId=control_preview_id, analyzerArn=analyzer_arn
        )["findings"]
        control_findings = [
            f for f in all_control_findings
            if f["resourceType"] == "AWS::S3::Bucket" and f.get("resource") == control_bucket_arn and f.get("isPublic")
        ]
        if control_findings:
            break
        time.sleep(3.0)
    assert control_findings, (
        f"positive control failed: expected a public finding for {control_bucket_arn}, "
        f"got findings={all_control_findings}"
    )

    private_findings = aa.list_access_preview_findings(
        accessPreviewId=private_preview_id, analyzerArn=analyzer_arn
    )["findings"]
    private_bucket_findings = [f for f in private_findings if f["resourceType"] == "AWS::S3::Bucket"]
    assert private_bucket_findings == [], (
        f"expected no external-access findings for a same-account-only policy on "
        f"{private_bucket_arn}, got {private_bucket_findings}"
    )


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

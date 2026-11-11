"""access-preview-detects-public-s3-bucket-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "access-preview-detects-public-s3-bucket-policy"
GROUP = "data-plane"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """CreateAccessPreview actually analyzes a proposed S3 bucket policy: a policy that
    grants Principal "*" access produces a COMPLETED preview with an isPublic finding for
    that bucket, without the bucket ever needing to exist."""
    aa = ctx.client("accessanalyzer")
    analyzer_name = ctx.unique_name("sim2real-aa-preview-pub-")
    analyzer_arn = aa.create_analyzer(
        analyzerName=analyzer_name, type="ACCOUNT", tags={"sim2real": CHECK}
    )["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=analyzer_name))
    _poll_analyzer_status(ctx, analyzer_name)

    bucket_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-aa-pub-bucket-')}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"{bucket_arn}/*",
        }],
    }
    preview_id = aa.create_access_preview(
        analyzerArn=analyzer_arn,
        configurations={
            bucket_arn: {
                "s3Bucket": {
                    "bucketPolicy": json.dumps(policy),
                    # New-bucket default for BPA is "false"; pin it explicitly so the
                    # public grant in the policy isn't masked by an ambiguous default.
                    "bucketPublicAccessBlock": {
                        "ignorePublicAcls": False,
                        "restrictPublicBuckets": False,
                    },
                }
            }
        },
    )["id"]

    status = _poll_preview_status(ctx, analyzer_arn, preview_id)
    assert status == "COMPLETED", f"access preview ended in status={status}"

    # Finding materialization can lag a beat behind the preview's own COMPLETED status,
    # so poll the findings list itself rather than querying it exactly once.
    public_bucket_findings: list = []
    all_findings: list = []
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        all_findings = aa.list_access_preview_findings(accessPreviewId=preview_id, analyzerArn=analyzer_arn)["findings"]
        public_bucket_findings = [
            f for f in all_findings if f["resourceType"] == "AWS::S3::Bucket" and f.get("isPublic")
        ]
        if public_bucket_findings:
            break
        time.sleep(3.0)
    assert public_bucket_findings, f"expected a public S3 bucket finding, got findings={all_findings}"


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

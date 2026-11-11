"""generated-template-timestamp-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "generated-template-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """CreationTime and LastUpdatedTime on a generated (IaC-generator) template
    are stable, exact values -- repeated DescribeGeneratedTemplate calls return
    byte-identical timestamps rather than a freshly computed 'now' each call."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-behav-gentpl-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    template_name = ctx.unique_name("sim2real-behav-gentpl-")
    cfn.create_generated_template(
        GeneratedTemplateName=template_name,
        Resources=[
            {
                "ResourceType": "AWS::S3::Bucket",
                "ResourceIdentifier": {"BucketName": bucket_name},
            }
        ],
    )
    ctx.on_cleanup(lambda: cfn.delete_generated_template(GeneratedTemplateName=template_name))

    first = _wait_for_generated_template_complete(ctx, template_name, timeout_s=180)

    # Three consecutive reads spaced 1s apart: a target that computes a fresh 'now'
    # per-call would drift across at least one of them, not just the first re-read.
    for _ in range(3):
        time.sleep(1.0)
        reread = cfn.describe_generated_template(GeneratedTemplateName=template_name)
        assert reread["Status"] == "COMPLETE", f"expected COMPLETE, got {reread['Status']!r}"
        assert reread["CreationTime"] == first["CreationTime"], (
            f"CreationTime drifted between reads: {first['CreationTime']!r} != {reread['CreationTime']!r}"
        )
        assert reread["LastUpdatedTime"] == first["LastUpdatedTime"], (
            f"LastUpdatedTime drifted between reads: {first['LastUpdatedTime']!r} != {reread['LastUpdatedTime']!r}"
        )

    assert first["CreationTime"] <= first["LastUpdatedTime"], (
        f"CreationTime must not be after LastUpdatedTime: "
        f"{first['CreationTime']!r} > {first['LastUpdatedTime']!r}"
    )


def _wait_for_generated_template_complete(ctx, template_name, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_generated_template(GeneratedTemplateName=template_name)
        last_status = resp["Status"]
        if last_status == "COMPLETE":
            return resp
        if last_status == "FAILED":
            raise AssertionError(f"generated template failed: {resp.get('StatusReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"generated template {template_name} never completed, last status {last_status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

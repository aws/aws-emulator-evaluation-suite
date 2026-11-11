"""update-receipt-rule-invalid-s3-configuration-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-receipt-rule-invalid-s3-configuration-rejected"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateReceiptRule with an S3Action on a bucket that does not exist yet fails with
    InvalidS3Configuration "No such bucket: <bucket>" and leaves the rule at its last update; once that
    bucket exists and grants SES write access, the identical call succeeds."""
    ses = ctx.client("ses")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    rule_set_name = ctx.unique_name("sim2real-ses-rs-")
    rule_name = ctx.unique_name("sim2real-ses-rule-")
    writable_bucket = ctx.unique_name("sim2real-ses-s3-a-")
    unwritable_bucket = ctx.unique_name("sim2real-ses-s3-b-")

    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    _create_writable_bucket(ctx, s3, writable_bucket, account_id, region, rule_set_name, rule_name)

    base_rule = {
        "Name": rule_name,
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [],
        "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v1"}}],
        "ScanEnabled": False,
    }
    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=base_rule)

    writable_rule = dict(base_rule)
    writable_rule["Actions"] = [{"S3Action": {"BucketName": writable_bucket}}]
    _retry_s3_config(
        lambda: ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=writable_rule),
        description="update to the writable bucket",
    )
    control = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert control["Actions"] == writable_rule["Actions"], (
        f"the positive-control update to a writable bucket did not take effect: {control['Actions']!r}"
    )

    bad_rule = dict(base_rule)
    bad_rule["Actions"] = [{"S3Action": {"BucketName": unwritable_bucket}}]
    code = _error_code(
        lambda: ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=bad_rule)
    )
    assert code == ("InvalidS3Configuration", f"No such bucket: {unwritable_bucket}"), (
        f"expected InvalidS3Configuration, got {code!r}"
    )

    # The rule stays at the last-good state, not the rejected bucket nor the original AddHeaderAction.
    described = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert described["Actions"] == writable_rule["Actions"], (
        "rejected update mutated the stored rule's actions away from the last-good state: "
        f"{described['Actions']!r}"
    )

    _create_writable_bucket(ctx, s3, unwritable_bucket, account_id, region, rule_set_name, rule_name)
    _retry_s3_config(
        lambda: ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=bad_rule),
        description="identical update after granting the bucket write access",
    )
    restored = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_name)["Rule"]
    assert restored["Actions"] == bad_rule["Actions"], (
        f"the identical update did not take effect once the bucket became writable: {restored['Actions']!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        if error.get("Code"):
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _create_writable_bucket(ctx, s3, bucket, account_id, region, rule_set_name, rule_name) -> None:
    """Create `bucket` and grant SES the write permission the rule's S3 action requires.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html"""
    if region == "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint of "us-east-1"; it must be omitted.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSESPuts",
                "Effect": "Allow",
                "Principal": {"Service": "ses.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceAccount": account_id,
                        "AWS:SourceArn": (
                            f"arn:aws:ses:{region}:{account_id}:receipt-rule-set/"
                            f"{rule_set_name}:receipt-rule/{rule_name}"
                        ),
                    }
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _delete_bucket(s3, bucket) -> None:
    objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _retry_s3_config(fn, *, description: str, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Retry fn() while SES reports InvalidS3Configuration; a new bucket policy is eventually
    consistent, so the wait is bounded by timeout_s."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while True:
        try:
            return fn()
        except Exception as exc:
            last_code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if last_code != "InvalidS3Configuration" or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} did not succeed within {timeout_s}s; last error {last_code!r}"
                ) from exc
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

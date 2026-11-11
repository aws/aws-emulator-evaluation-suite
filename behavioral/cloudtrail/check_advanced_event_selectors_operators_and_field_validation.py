"""advanced-event-selectors-operators-and-field-validation."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _error_code_and_message(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket}
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "advanced-event-selectors-operators-and-field-validation"
GROUP = 'trail-config'
SERVICES = ['cloudtrail']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each malformed advanced selector is refused with InvalidEventSelectorsException and its
    exact message, and GetEventSelectors still returns the previously applied selector verbatim,
    so a refused PutEventSelectors never partially applies.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")

    name = ctx.unique_name("sim2real-behav-ct-trail-")
    created = _create_trail(ctx, ct, s3, name)
    minted_arn = created["TrailARN"]
    assert minted_arn.endswith(f":trail/{name}"), minted_arn

    # A management-only baseline (no data-event charges); multi-value NotEquals also pins list order.
    baseline = [
        {
            "Name": "sim2real-management-not-kms-or-rdsdata",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Management"]},
                {
                    "Field": "eventSource",
                    "NotEquals": ["kms.amazonaws.com", "rdsdata.amazonaws.com"],
                },
                {"Field": "readOnly", "Equals": ["false"]},
            ],
        }
    ]
    put = _call(
        lambda: ct.put_event_selectors(TrailName=name, AdvancedEventSelectors=baseline)
    )
    assert put["TrailARN"] == minted_arn, put["TrailARN"]
    assert put["AdvancedEventSelectors"] == baseline, put["AdvancedEventSelectors"]

    def assert_baseline_intact():
        """The live selector must still be exactly what was last successfully applied."""
        got = _call(lambda: ct.get_event_selectors(TrailName=name))
        assert got["TrailARN"] == minted_arn, got["TrailARN"]
        assert "EventSelectors" not in got, got.get("EventSelectors")
        assert got["AdvancedEventSelectors"] == baseline, got["AdvancedEventSelectors"]

    assert_baseline_intact()

    refusal_messages = []

    def refuse(selectors, expected_message, why):
        code, message = _error_code_and_message(
            lambda: ct.put_event_selectors(
                TrailName=name, AdvancedEventSelectors=selectors
            )
        )
        assert code == "InvalidEventSelectorsException", f"{why}: got {code}"
        assert message == expected_message, f"{why}: message {message!r}"
        refusal_messages.append(message)
        # Effect absent: no partial application, no rollback to a default.
        assert_baseline_intact()

    # 1. The mandatory eventCategory field selector is missing.
    refuse(
        [
            {
                "Name": "sim2real-missing-event-category",
                "FieldSelectors": [{"Field": "readOnly", "Equals": ["false"]}],
            }
        ],
        "The following fields are required: [eventCategory].",
        "selector with no eventCategory was accepted",
    )

    # 2. A field name that does not exist in the selector language at all.
    refuse(
        [
            {
                "Name": "sim2real-unknown-field",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management"]},
                    {"Field": "notARealSelectorField", "Equals": ["anything"]},
                ],
            }
        ],
        "The following field is not allowed when the eventCategory field value equals Management: notARealSelectorField.",
        "selector naming a nonexistent field was accepted",
    )

    # 3. A real field that is not supported for eventCategory=Management. This is the case
    #    an emulator with a flat field allowlist gets wrong: the name is valid, the
    #    category context is not.
    refuse(
        [
            {
                "Name": "sim2real-event-name-on-management",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management"]},
                    {"Field": "eventName", "Equals": ["PutEventSelectors"]},
                ],
            }
        ],
        "The following field is not allowed when the eventCategory field value equals Management: eventName.",
        "eventName on a Management selector was accepted",
    )

    # 4. A field selector with no comparison operator at all. Only `Field` is required by
    #    the Smithy shape, so this reaches the service and must be refused there — an
    #    emulator that treats "no operator" as "match everything" is over-permissive.
    refuse(
        [
            {
                "Name": "sim2real-no-operator",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management"]},
                    {"Field": "readOnly"},
                ],
            }
        ],
        "One or more of the selectors for the readOnly field is empty.",
        "field selector with no operator was accepted",
    )

    # 5. Two event categories in one selector. eventCategory takes exactly one value.
    refuse(
        [
            {
                "Name": "sim2real-two-categories",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management", "Data"]}
                ],
            }
        ],
        "There are too many values specified for eventCategory. The eventCategory field can have a maximum of 1 values.",
        "selector with two event categories was accepted",
    )

    # 6. An unsupported resources.type value. Deliberately a type that does not exist, so
    #    this can never enable billable data-event logging.
    refuse(
        [
            {
                "Name": "sim2real-unsupported-resource-type",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": ["AWS::Sim2Real::Nonexistent"]},
                ],
            }
        ],
        "The resources.type field value is not valid.",
        "selector naming an unsupported resources.type was accepted",
    )

    assert len(refusal_messages) == 6, refusal_messages

    # A different valid selector still applies, so the refusals did not wedge the trail.
    replacement = [
        {
            "Name": "sim2real-management-read-only",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Management"]},
                {"Field": "readOnly", "Equals": ["true"]},
            ],
        }
    ]
    applied = _call(
        lambda: ct.put_event_selectors(TrailName=name, AdvancedEventSelectors=replacement)
    )
    assert applied["TrailARN"] == minted_arn, applied["TrailARN"]
    assert applied["AdvancedEventSelectors"] == replacement, applied["AdvancedEventSelectors"]
    final = _call(lambda: ct.get_event_selectors(TrailName=name))
    assert final["AdvancedEventSelectors"] == replacement, final["AdvancedEventSelectors"]
    assert "EventSelectors" not in final, final.get("EventSelectors")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""start-job-invalid-role-arn-pattern-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-job-invalid-role-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehendmedical"]


def _error_code_and_message(fn):
    # No ParamValidationError branch: both calls below are engineered to reach the SERVICE (either
    # via a client with parameter validation disabled, or a syntactically valid arn), so a
    # ParamValidationError here would mean that engineering failed -- it must propagate.
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cmed-arn-").lower()
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; this compares
    # against ctx.region rather than assuming it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=b"Patient takes lisinopril 10 mg daily.")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="input/doc.txt"))
    return bucket


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartPHIDetectionJob with a DataAccessRoleArn that fails the IAM ARN pattern and with a well-formed
    ARN of an absent role both fail with InvalidRequestException, told apart by their distinct exact
    messages (validation off in the client, so the service judges the pattern)."""
    cm = ctx.client("comprehendmedical")
    unvalidated = ctx.client("comprehendmedical", config=Config(parameter_validation=False))
    bucket = _create_bucket(ctx)
    input_cfg = {"S3Bucket": bucket, "S3Key": "input/doc.txt"}
    output_cfg = {"S3Bucket": bucket, "S3Key": "output/"}

    malformed_arn = "not-a-valid-arn"
    code1, message1 = _error_code_and_message(
        lambda: unvalidated.start_phi_detection_job(
            InputDataConfig=input_cfg,
            OutputDataConfig=output_cfg,
            DataAccessRoleArn=malformed_arn,
            LanguageCode="en",
        )
    )
    assert code1 == "InvalidRequestException", f"expected InvalidRequestException for a malformed arn, got {code1}"
    expected1 = "DATA_ACCESS_ROLE_ARN_INVALID: The provided dataAccessRoleArn is invalid."
    assert message1 == expected1, f"expected message {expected1!r}, got {message1!r}"

    # Distinguishing control: a syntactically VALID arn naming a role that simply doesn't exist gets
    # the SAME top-level code but a DIFFERENT message, proving the service tells syntax rejection
    # apart from resource resolution even though it reuses the error code for both. The absent role
    # must live in THIS account (not a foreign placeholder) or the service instead rejects it for
    # cross-account PassRole, which is a different contract than the one this check measures.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    well_formed_but_absent_arn = f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-role"
    code2, message2 = _error_code_and_message(
        lambda: cm.start_phi_detection_job(
            InputDataConfig=input_cfg,
            OutputDataConfig=output_cfg,
            DataAccessRoleArn=well_formed_but_absent_arn,
            LanguageCode="en",
        )
    )
    assert code2 == "InvalidRequestException", f"expected InvalidRequestException for an absent role, got {code2}"
    expected2 = (
        "The provided IAM role does not trust Comprehend Medical service principle. "
        "See: https://docs.aws.amazon.com/comprehend-medical/latest/dev/textanalysis-batchapi.html#batch-iam"
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"
    assert message2 != message1, (
        f"expected the absent-role rejection to carry a message distinct from the malformed-arn "
        f"rejection, got the same message {message2!r} for both"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

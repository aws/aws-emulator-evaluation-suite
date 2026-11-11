"""get-async-invoke-malformed-arn-rejected-distinctly-from-absent-job."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-async-invoke-malformed-arn-rejected-distinctly-from-absent-job"
GROUP = 'async_invoke_rejected'
SERVICES = ['bedrock-runtime']

_ASYNC_MODEL = "luma.ray-v2:0"
_TERMINAL = ("Completed", "Failed")
_TERMINAL_TIMEOUT_S = 120.0


def _error(fn):
    """Return (code, message) for a ClientError; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call was expected to be refused but returned success")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetAsyncInvoke refuses a malformed ARN and an absent job with distinct messages.
    Both are ValidationException: the operation declares no ResourceNotFoundException."""
    rt = ctx.client("bedrock-runtime")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-brt-getarn-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bedrock-runtime-get-async-invoke-arn"}]})

    def _drop_bucket():
        token = None
        while True:
            page = s3.list_objects_v2(
                Bucket=bucket, **({"ContinuationToken": token} if token else {})
            )
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            token = page.get("NextContinuationToken")
            if not token:
                break
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_drop_bucket)

    real_arn = rt.start_async_invoke(
        modelId=_ASYNC_MODEL,
        modelInput={},
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}},
    )["invocationArn"]

    # Positive control: this ARN resolves.
    resolved = rt.get_async_invoke(invocationArn=real_arn)
    assert resolved["invocationArn"] == real_arn, (
        f"positive control: GetAsyncInvoke({real_arn!r}) returned "
        f"{resolved['invocationArn']!r}"
    )

    prefix, _, invocation_id = real_arn.rpartition("/")
    absent_arn = f"{prefix}/{'z' * len(invocation_id)}"
    assert absent_arn != real_arn, (
        f"failed to derive an absent ARN distinct from {real_arn!r}"
    )

    # Break exactly one thing: the invocation id, keeping partition, region and account.
    absent_code, absent_message = _error(
        lambda: rt.get_async_invoke(invocationArn=absent_arn)
    )
    assert absent_code == "ValidationException", (
        f"a well-formed ARN naming no job should be a ValidationException, got {absent_code!r}"
    )
    assert absent_message == "jobArn: {} is not found.", (
        f"unexpected refusal message for an absent job: {absent_message!r}"
    )

    # Break something else entirely: an identifier that is not ARN-shaped at all.
    malformed_code, malformed_message = _error(
        lambda: rt.get_async_invoke(invocationArn="sim2real-not-an-arn")
    )
    assert malformed_code == "ValidationException", (
        f"a non-ARN identifier should be a ValidationException, got {malformed_code!r}"
    )
    assert malformed_message == "The provided Async Invoke arn is not valid", (
        f"unexpected refusal message for a malformed ARN: {malformed_message!r}"
    )

    assert absent_message != malformed_message, (
        f"a malformed ARN and an absent job both reported {absent_message!r}, so a caller cannot "
        f"tell a typo from a deleted job"
    )

    # Let the job settle so cleanup does not race a writer into the bucket it is emptying.
    deadline = time.monotonic() + _TERMINAL_TIMEOUT_S
    status = rt.get_async_invoke(invocationArn=real_arn)["status"]
    while status not in _TERMINAL:
        assert time.monotonic() < deadline, (
            f"async invoke {real_arn!r} never reached a terminal state within "
            f"{_TERMINAL_TIMEOUT_S}s; last status was {status!r}"
        )
        time.sleep(3.0)
        status = rt.get_async_invoke(invocationArn=real_arn)["status"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

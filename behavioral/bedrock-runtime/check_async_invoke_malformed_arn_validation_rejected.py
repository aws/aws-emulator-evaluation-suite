"""async-invoke-malformed-arn-validation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "async-invoke-malformed-arn-validation-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

_ASYNC_MODEL = "luma.ray-v2:0"
_TERMINAL = ("Completed", "Failed")
_TERMINAL_TIMEOUT_S = 120.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAsyncInvoke rejects an invocationArn that doesn't match the required
    arn:...:async-invoke/{id} pattern with ValidationException."""
    brt = ctx.client("bedrock-runtime")
    bucket = _create_output_bucket(ctx)
    real_arn = brt.start_async_invoke(
        modelId=_ASYNC_MODEL,
        modelInput={},
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}},
    )["invocationArn"]

    # positive control: GetAsyncInvoke itself resolves a real, well-formed ARN --
    # without this, a target that rejects every GetAsyncInvoke call would pass just
    # as well as one that specifically rejects malformed input.
    control = brt.get_async_invoke(invocationArn=real_arn)
    assert control["invocationArn"] == real_arn, (
        f"positive control: GetAsyncInvoke({real_arn!r}) returned {control['invocationArn']!r}"
    )

    code, message = _error(lambda: brt.get_async_invoke(invocationArn="not-an-arn"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == 'The provided Async Invoke arn is not valid', f"unexpected refusal message {message!r}"

    # effect absent: the real invocation is unaffected by the rejected lookup
    control_again = brt.get_async_invoke(invocationArn=real_arn)
    assert control_again["invocationArn"] == real_arn, (
        f"after the rejected lookup, GetAsyncInvoke({real_arn!r}) returned "
        f"{control_again['invocationArn']!r}"
    )

    _await_terminal(brt, real_arn)


def _await_terminal(brt, arn: str) -> None:
    """Let the job settle so cleanup does not race a writer into the bucket it is emptying."""
    deadline = time.monotonic() + _TERMINAL_TIMEOUT_S
    job = brt.get_async_invoke(invocationArn=arn)
    while job["status"] not in _TERMINAL:
        assert time.monotonic() < deadline, (
            f"async invoke {arn!r} never reached a terminal state within "
            f"{_TERMINAL_TIMEOUT_S}s; last status was {job['status']!r}"
        )
        time.sleep(3.0)
        job = brt.get_async_invoke(invocationArn=arn)


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-async-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("call was expected to be refused but returned success")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

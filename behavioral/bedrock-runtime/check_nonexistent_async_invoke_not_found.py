"""nonexistent-async-invoke-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "nonexistent-async-invoke-not-found"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAsyncInvoke on a well-formed but never-issued invocationArn in the caller's account
    returns ValidationException ('jobArn: {} is not found.') on two attempts, while a real
    invocation resolves before and after the failed lookups.
    """
    bucket = _create_output_bucket(ctx)
    arn = _start_video_invoke(ctx, bucket)
    br = ctx.client("bedrock-runtime")

    # positive control: a real, just-created invocation resolves
    control = br.get_async_invoke(invocationArn=arn)
    assert control["invocationArn"] == arn, (
        f"positive control: GetAsyncInvoke({arn!r}) returned {control['invocationArn']!r}"
    )

    # break exactly one thing: a syntactically valid arn whose id segment was never issued
    fake_arn = arn[:-12] + "000000000000"
    assert fake_arn != arn, f"failed to derive a fabricated arn distinct from {arn!r}"

    code, message = _error(lambda: br.get_async_invoke(invocationArn=fake_arn))
    assert code == "ValidationException", (
        f"expected ValidationException for a well-formed but absent invocationArn, got {code!r}"
    )
    assert message == "jobArn: {} is not found.", (
        f"unexpected refusal message for an absent invocationArn: {message!r}"
    )

    # effect absent: the fabricated arn still resolves to nothing, identically, on a second attempt
    code_again, message_again = _error(lambda: br.get_async_invoke(invocationArn=fake_arn))
    assert (code_again, message_again) == (code, message), (
        f"absence was not stable across two reads: first ({code!r}, {message!r}), "
        f"second ({code_again!r}, {message_again!r})"
    )

    # the real invocation is unaffected by the failed lookups
    control_again = br.get_async_invoke(invocationArn=arn)
    assert control_again["invocationArn"] == arn, (
        f"real invocation {arn!r} was affected by the failed lookups: "
        f"GetAsyncInvoke now returns {control_again['invocationArn']!r}"
    )


def _create_output_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # S3 rejects an explicit LocationConstraint for us-east-1 specifically; every other
    # region requires one. This is the bucket's own home region, not a pinned check region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "nonexistent-async-invoke-not-found"}]}
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _start_video_invoke(ctx: Any, bucket_name: str) -> str:
    br = ctx.client("bedrock-runtime")
    output_config = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_name}/"}}
    resp = br.start_async_invoke(
        modelId="luma.ray-v2:0",
        modelInput={},
        outputDataConfig=output_config,
    )
    return resp["invocationArn"]


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

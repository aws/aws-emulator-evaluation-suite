"""cross-account-async-invoke-not-visible."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-account-async-invoke-not-visible"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

# luma.ray-v2:0 is a current video-capable async model in this suite's region; a 5 s job
# completes in about 71 s.
ASYNC_MODEL = "luma.ray-v2:0"

_TERMINAL = ("Completed", "Failed")
_TERMINAL_TIMEOUT_S = 240.0


def _error(fn):
    """Return (code, message) of the ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected GetAsyncInvoke to be refused, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAsyncInvokes returns only the caller's own invocations, including one just created.

    GetAsyncInvoke on another account's ARN is AccessDeniedException, while an unknown ARN in the
    caller's own account is ValidationException: "not yours" is distinguished from "not found"."""
    bedrock = ctx.client("bedrock-runtime")
    sts = ctx.client("sts")
    own_account = sts.get_caller_identity()["Account"]
    region = ctx.region

    bucket = _create_output_bucket(ctx)
    real_arn = _start_video_invoke(ctx, bucket)

    # Positive control: the read APIs are not broadly broken/denying -- a real, just-created
    # invocation in this account resolves cleanly.
    control = bedrock.get_async_invoke(invocationArn=real_arn)
    assert control["invocationArn"] == real_arn, (
        f"positive control: GetAsyncInvoke({real_arn!r}) returned {control['invocationArn']!r}"
    )

    # ListAsyncInvokes never accepts a foreign account identifier -- the real invocation shows
    # up, and every entry it returns is scoped to the caller's own account.
    list_resp = bedrock.list_async_invokes(maxResults=50)
    listed_arns = {item["invocationArn"] for item in list_resp.get("asyncInvokeSummaries", [])}
    assert real_arn in listed_arns, f"ListAsyncInvokes omitted the invocation it just created: {real_arn}"
    for arn in listed_arns:
        assert f":{own_account}:" in arn, f"ListAsyncInvokes leaked a foreign-account ARN: {arn}"

    fake_id_own = "aaaaaaaaaaaa"
    fake_id_other = "bbbbbbbbbbbb"
    other_account = "999999999999" if own_account != "999999999999" else "888888888888"

    own_account_arn = f"arn:aws:bedrock:{region}:{own_account}:async-invoke/{fake_id_own}"
    other_account_arn = f"arn:aws:bedrock:{region}:{other_account}:async-invoke/{fake_id_other}"

    # An unrecognized invocation ARN in the caller's OWN account is a ValidationException --
    # the service recognizes the ARN as belonging to the caller and reports it as simply
    # missing, never a ResourceNotFoundException.
    def _get_own():
        bedrock.get_async_invoke(invocationArn=own_account_arn)

    own_code, own_message = _error(_get_own)
    assert own_code == "ValidationException", f"expected ValidationException, got {own_code}"
    assert own_message == 'jobArn: {} is not found.', f"unexpected refusal message {own_message!r}"

    # A different account's async-invoke ARN is denied outright -- never surfaced as merely
    # "not found", and never returns that account's data.
    def _get_other():
        bedrock.get_async_invoke(invocationArn=other_account_arn)

    other_code, other_message = _error(_get_other)
    assert other_code == "AccessDeniedException", f"expected AccessDeniedException, got {other_code}"
    assert other_message == 'The provided resource ARN is from a different account.', f"unexpected refusal message {other_message!r}"

    # The real invocation is unaffected by the failed lookups against fabricated ARNs.
    control_again = bedrock.get_async_invoke(invocationArn=real_arn)
    assert control_again["invocationArn"] == real_arn, (
        f"real invocation {real_arn!r} was affected by lookups against fabricated ARNs: "
        f"re-read returned {control_again['invocationArn']!r}"
    )

    # Let the job settle before cleanup empties the bucket, so cleanup does not race a writer.
    left = ctx.time_left()
    deadline = time.monotonic() + (_TERMINAL_TIMEOUT_S if left is None else min(_TERMINAL_TIMEOUT_S, left))
    status = bedrock.get_async_invoke(invocationArn=real_arn)["status"]
    while status not in _TERMINAL:
        assert time.monotonic() < deadline, (
            f"async invoke {real_arn!r} never reached a terminal state within "
            f"{_TERMINAL_TIMEOUT_S}s; last status was {status!r}"
        )
        time.sleep(3.0)
        status = bedrock.get_async_invoke(invocationArn=real_arn)["status"]


def _create_output_bucket(ctx: Any) -> str:
    # In the region the job runs in, so Bedrock's async-invoke output destination is reachable.
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-xacct-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "bedrock-cross-account-async-invoke-not-visible"}]},
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _start_video_invoke(
    ctx: Any,
    bucket_name: str,
    prompt: str = "Closeup of a cute old steampunk robot. Camera zoom in.",
) -> str:
    br = ctx.client("bedrock-runtime")
    model_input = {
        "prompt": prompt,
        "aspect_ratio": "16:9",
        "loop": False,
        "duration": "5s",
        "resolution": "540p",
    }
    output_config = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_name}/"}}
    resp = _start_with_backoff(
        ctx,
        lambda: br.start_async_invoke(
            modelId=ASYNC_MODEL,
            modelInput=model_input,
            outputDataConfig=output_config,
        )
    )
    return resp["invocationArn"]


def _start_with_backoff(ctx, fn):
    """Retry ONLY a throttle: an account admits very few concurrent async invocations, so
    async-invoke jobs started at once can throttle each other."""
    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""malformed-invocation-arn-validation-rejected."""
from __future__ import annotations

import random
from typing import Any

from behavioral_harness import tags

CHECK = "malformed-invocation-arn-validation-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAsyncInvoke rejects an invocationArn that doesn't match the required ARN pattern with ValidationException."""
    # Nova Reel is not invocable in every commercial region (elsewhere StartAsyncInvoke raises
    # ValidationException("The provided model identifier is invalid")); us-east-1 is where it resolves, so both the model and its output bucket are
    # pinned there rather than following ctx.region.
    bucket = _create_output_bucket(ctx)
    arn = _start_video_invoke(ctx, bucket)
    br = ctx.client("bedrock-runtime", region="us-east-1")

    # positive control: a syntactically valid, real arn resolves without error
    control = br.get_async_invoke(invocationArn=arn)
    assert control["invocationArn"] == arn, (
        f"positive control: GetAsyncInvoke({arn!r}) returned {control['invocationArn']!r}"
    )

    # break exactly one thing: pass a string that doesn't match the async-invoke ARN pattern
    malformed = "not-an-async-invoke-arn"

    code, message = _error(lambda: br.get_async_invoke(invocationArn=malformed))
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed invocationArn, got {code!r} ({message!r})"
    )
    assert message == "The provided Async Invoke arn is not valid", (
        f"unexpected refusal message for a malformed invocationArn: {message!r}"
    )

    # effect absent: the malformed lookup is rejected consistently, never resolved
    code_again, message_again = _error(lambda: br.get_async_invoke(invocationArn=malformed))
    assert code_again == "ValidationException", (
        f"malformed-ARN rejection is not stable: second attempt got {code_again!r} ({message_again!r})"
    )

    # the real invocation is unaffected by the rejected lookups
    control_again = br.get_async_invoke(invocationArn=arn)
    assert control_again["invocationArn"] == arn, (
        f"real invocation {arn!r} was disturbed by the rejected malformed lookups: "
        f"got {control_again['invocationArn']!r}"
    )


def _create_output_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3", region="us-east-1")
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs: dict[str, Any] = {"Bucket": name}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
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
    br = ctx.client("bedrock-runtime", region="us-east-1")
    seed = random.randint(0, 2147483646)
    model_input = {
        "taskType": "TEXT_VIDEO",
        "textToVideoParams": {"text": prompt},
        "videoGenerationConfig": {
            "fps": 24,
            "durationSeconds": 6,
            "dimension": "1280x720",
            "seed": seed,
        },
    }
    output_config = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_name}/"}}
    resp = br.start_async_invoke(
        modelId="amazon.nova-reel-v1:1",
        modelInput=model_input,
        outputDataConfig=output_config,
    )
    return resp["invocationArn"]


def _error(fn):
    """Return (code, message) for a ClientError; raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

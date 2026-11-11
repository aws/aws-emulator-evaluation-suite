"""list-and-get-async-invoke-validation-boundaries-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-and-get-async-invoke-validation-boundaries-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAsyncInvokes refuses maxResults=1001 and GetAsyncInvoke refuses an invocationArn off its
    pattern, both with ValidationException and the exact message, while ListAsyncInvokes with a
    valid maxResults succeeds.
    """
    brt = ctx.client("bedrock-runtime")

    list_code, list_message = _error_code(lambda: brt.list_async_invokes(maxResults=1001))
    assert list_code == "ValidationException", list_code
    assert list_message == (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    ), list_message

    get_code, get_message = _error_code(lambda: brt.get_async_invoke(invocationArn="not-a-valid-arn"))
    assert get_code == "ValidationException", get_code
    assert get_message == "The provided Async Invoke arn is not valid", get_message

    control = brt.list_async_invokes(maxResults=5)
    assert "asyncInvokeSummaries" in control, (
        f"expected a well-formed ListAsyncInvokes to return asyncInvokeSummaries, got keys {sorted(control)}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("call was expected to be refused but returned success")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

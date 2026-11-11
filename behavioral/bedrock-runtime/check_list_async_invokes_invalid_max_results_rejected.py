"""list-async-invokes-invalid-max-results-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-async-invokes-invalid-max-results-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

_MSG_ZERO = (
    "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
    "Member must have value greater than or equal to 1"
)
_MSG_OVER = (
    "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy constraint: "
    "Member must have value less than or equal to 1000"
)
_MSG_TOKEN = "Invalid pagination token was passed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAsyncInvokes, sent past client-side validation, refuses maxResults=0, an over-large
    maxResults and a malformed nextToken with ValidationException and the exact message for each,
    while a valid call succeeds.
    """
    brt = ctx.client("bedrock-runtime")
    raw = ctx.client(
        "bedrock-runtime",
        config=Config(retries={"max_attempts": 1}, parameter_validation=False),
    )

    code_zero, msg_zero = _error_code_and_message(lambda: raw.list_async_invokes(maxResults=0))
    assert code_zero == "ValidationException", f"expected ValidationException, got {code_zero}"
    assert msg_zero == _MSG_ZERO, f"expected message {_MSG_ZERO!r}, got {msg_zero!r}"

    # an over-large maxResults passes client-side validation and reaches the
    # real service, which rejects it there with ValidationException
    code, msg = _error_code_and_message(lambda: brt.list_async_invokes(maxResults=1001))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == _MSG_OVER, f"expected message {_MSG_OVER!r}, got {msg!r}"

    # malformed nextToken is not range-constrained client-side, so this round-trips
    # to the real service and is rejected there with ValidationException
    code_token, msg_token = _error_code_and_message(
        lambda: brt.list_async_invokes(nextToken="not-a-valid-token!!")
    )
    assert code_token == "ValidationException", f"expected ValidationException, got {code_token}"
    assert msg_token == _MSG_TOKEN, f"expected message {_MSG_TOKEN!r}, got {msg_token!r}"

    # positive control: an in-range call still succeeds
    control = brt.list_async_invokes(maxResults=5)
    assert "asyncInvokeSummaries" in control


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

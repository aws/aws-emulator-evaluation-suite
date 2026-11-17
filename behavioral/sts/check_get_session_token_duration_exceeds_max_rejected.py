"""get-session-token-duration-exceeds-max-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-duration-exceeds-max-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; raises AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSessionToken refuses a DurationSeconds above the 129600s maximum with the exact
    validation message, while the maximum value itself still mints usable credentials."""

    # Client-side parameter validation off, so STS's own input validation answers instead of a
    # local ParamValidationError.
    sts = ctx.client("sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False))

    # Positive control: the boundary value itself is accepted and issues real credentials,
    # isolating "one second past the maximum" as the one thing the refusal below is about.
    at_max = sts.get_session_token(DurationSeconds=129600)
    assert at_max["Credentials"]["AccessKeyId"].startswith("ASIA"), (
        f"expected a temporary (ASIA-prefixed) access key at the boundary duration, got "
        f"{at_max['Credentials']['AccessKeyId']!r}"
    )

    code, message = _refusal(lambda: sts.get_session_token(DurationSeconds=129601))
    assert code == "ValidationError", (
        f"expected ValidationError for DurationSeconds one past the max, got {code}"
    )
    assert message == (
        "1 validation error detected: Value '129601' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value less than or equal to 129600"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""update-account-settings-invalid-value-fails."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.config import Config
from botocore.exceptions import ClientError

CHECK = "update-account-settings-invalid-value-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:kinesis-account-settings")
def run(ctx) -> None:
    """UpdateAccountSettings with an invalid Status enum value fails with ValidationException
    (not InvalidArgumentException) and leaves the account's billing commitment unchanged."""
    kinesis = ctx.client("kinesis")

    # Positive control is read-only: on an account never opted in to minimum-throughput billing,
    # even UpdateAccountSettings(Status=DISABLED) fails with "Account isn't opted in."
    before = kinesis.describe_account_settings()
    assert "MinimumThroughputBillingCommitment" in before, (
        f"expected DescribeAccountSettings to include MinimumThroughputBillingCommitment, "
        f"got keys {sorted(before)!r}"
    )

    # Client-side validation is off so botocore does not block the bogus enum locally.
    raw = _client_without_param_validation(ctx, "kinesis")
    code, message = _error_code(
        lambda: raw.update_account_settings(
            MinimumThroughputBillingCommitment={"Status": "NEGATIVE-1"}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'NEGATIVE-1' at "
        "'minimumThroughputBillingCommitment.status' failed to satisfy constraint: "
        "Member must satisfy enum value set: [ENABLED, DISABLED]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected call did not change the account's commitment settings.
    after = kinesis.describe_account_settings()
    before_commitment = before.get("MinimumThroughputBillingCommitment")
    after_commitment = after.get("MinimumThroughputBillingCommitment")
    assert after_commitment == before_commitment, (
        f"expected MinimumThroughputBillingCommitment unchanged by the rejected call, "
        f"was {before_commitment!r}, now {after_commitment!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _client_without_param_validation(ctx, service: str):
    """ctx.client with botocore's local parameter (incl. enum) validation off, so a value the
    model forbids reaches the service instead of being rejected client-side."""
    return ctx.client(service, config=Config(parameter_validation=False, retries={"max_attempts": 1}))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


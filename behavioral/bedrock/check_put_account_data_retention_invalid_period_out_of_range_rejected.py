"""put-account-data-retention-invalid-period-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-account-data-retention-invalid-period-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:bedrock-account-data-retention")
def run(ctx) -> None:
    """PutAccountDataRetention rejects an unsupported mode with ValidationException.

    `mode` is a closed enum with no duration field; the rejected call leaves the mode unchanged,
    and a valid mode is still accepted and persists.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_PutAccountDataRetention.html
    """
    bedrock = ctx.client("bedrock")

    prior_mode = bedrock.get_account_data_retention()["mode"]
    # Account-wide singleton: restore the prior mode.
    ctx.on_cleanup(lambda: bedrock.put_account_data_retention(mode=prior_mode))

    code, message = _error(lambda: bedrock.put_account_data_retention(mode="thirty-seven-years"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "1 validation error detected: Value at 'mode' failed to satisfy constraint: Member must satisfy enum value set: [default, provider_data_share, none, aws_review, inherit]", f"unexpected rejection message: {message!r}"

    assert bedrock.get_account_data_retention()["mode"] == prior_mode

    # Positive control: a valid mode is accepted and persists.
    target_mode = "none" if prior_mode != "none" else "default"
    put_resp = bedrock.put_account_data_retention(mode=target_mode)
    assert put_resp["mode"] == target_mode
    assert bedrock.get_account_data_retention()["mode"] == target_mode


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

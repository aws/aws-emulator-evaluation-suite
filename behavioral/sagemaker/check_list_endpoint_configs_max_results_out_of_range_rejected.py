"""list-endpoint-configs-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags

CHECK = "list-endpoint-configs-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEndpointConfigs MaxResults=0 fails client-side with ParamValidationError and
    MaxResults=101 is refused with ValidationException and its exact message, while the
    boundaries 1 and 100 are accepted and return normally."""
    sm = ctx.client("sagemaker")
    nonce = ctx.unique_name("sim2real-behav-sm-epc-mr-")

    error_zero = _error(lambda: sm.list_endpoint_configs(NameContains=nonce, MaxResults=0))
    assert isinstance(error_zero, ParamValidationError), (
        f"expected MaxResults=0 to fail client-side with ParamValidationError, got {error_zero!r}"
    )

    code_over, message_over = _error_code_and_message(
        lambda: sm.list_endpoint_configs(NameContains=nonce, MaxResults=101)
    )
    assert code_over == "ValidationException", (
        f"expected MaxResults=101 to be refused with ValidationException, got {code_over!r}"
    )
    expected_message = (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 100"
    )
    assert message_over == expected_message, (
        f"expected the MaxResults=101 refusal's message to be {expected_message!r}, "
        f"got {message_over!r}"
    )

    # positive control: the documented boundaries are not range-rejected, and the nonce
    # scopes the query to a prefix no sibling run can occupy, so an empty result is a
    # property of the query rather than of the account.
    low = sm.list_endpoint_configs(NameContains=nonce, MaxResults=1)
    assert low["EndpointConfigs"] == [], (
        f"expected MaxResults=1 over the unused prefix {nonce!r} to return no configs, "
        f"got {low['EndpointConfigs']!r}"
    )
    high = sm.list_endpoint_configs(NameContains=nonce, MaxResults=100)
    assert high["EndpointConfigs"] == [], (
        f"expected MaxResults=100 over the unused prefix {nonce!r} to return no configs, "
        f"got {high['EndpointConfigs']!r}"
    )


def _error(fn):
    try:
        fn()
    except Exception as exc:  # captures both ParamValidationError and ClientError
        return exc
    raise AssertionError("expected the call to be refused, but it succeeded")


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected the call to raise a ClientError, it returned normally")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

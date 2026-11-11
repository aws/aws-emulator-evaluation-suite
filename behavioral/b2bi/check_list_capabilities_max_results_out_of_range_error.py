"""list-capabilities-max-results-out-of-range-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-capabilities-max-results-out-of-range-error"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCapabilities rejects a maxResults value outside the documented 1-100 range with
    ValidationException, while an in-range value on the same account still succeeds (positive
    control)."""
    b2bi = ctx.client("b2bi")

    code, message = _error(lambda: b2bi.list_capabilities(maxResults=101))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # maxResults=0 is below the API's minimum of 1, and that bound is baked into botocore's
    # own client-side parameter validator, which raises ParamValidationError before the request
    # ever leaves the SDK -- so the default client can never observe the SERVICE's rejection of
    # this value. Disable client-side validation so the out-of-range value actually reaches the
    # target and its server-side rejection is what gets asserted.
    unvalidated = _raw_client(ctx, "b2bi")
    zero_code, message = _error(lambda: unvalidated.list_capabilities(maxResults=0))
    assert zero_code == "ValidationException", f"expected ValidationException, got {zero_code!r}"
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: an in-range value is accepted and returns a well-formed page.
    ok = b2bi.list_capabilities(maxResults=5)
    assert "capabilities" in ok, f"expected a 'capabilities' key in the response, got {ok!r}"
    assert len(ok["capabilities"]) <= 5, (
        f"expected at most 5 capabilities for maxResults=5, got {len(ok['capabilities'])}"
    )


def _raw_client(ctx, service: str):
    """A client with client-side parameter validation disabled, so an out-of-range value is
    actually sent to the TARGET and the SERVER's rejection is observed, instead of botocore
    raising a local ParamValidationError before any request is made. Built through
    `ctx.client(..., config=...)` so the config is MERGED over the runner's base config and the
    client keeps the target's endpoint, credentials, region and TLS settings.
    """
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so a target that accepts the call fails loudly instead of mismatching."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

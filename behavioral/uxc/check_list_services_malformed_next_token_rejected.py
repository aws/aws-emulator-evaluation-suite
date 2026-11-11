"""list-services-malformed-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-services-malformed-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["uxc"]

_BOGUS_TOKEN_MESSAGE = (
    "Pagination token exception in operation 'ListServices': invalid payload wrapping schema 0"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A nextToken that satisfies the client-side length/pattern constraints but does not
    correspond to a real continuation cursor is rejected by the service with
    ValidationException, while a real token obtained from a prior page still works."""
    uxc = ctx.client("uxc")

    first_page = uxc.list_services(maxResults=1)
    real_token = first_page.get("nextToken")
    if not real_token:
        raise AssertionError(
            "ListServices catalog fits in a single page of 1 result; cannot obtain a real "
            "nextToken to use as the positive control for this check"
        )

    # Well-formed (length 32-512, charset-valid) but not a real cursor: must be rejected
    # server-side with ValidationException, not client-side ParamValidationError.
    bogus_token = "A" * 32
    code, message = _error(lambda: uxc.list_services(nextToken=bogus_token))
    assert code == "ValidationException", (
        f"expected ValidationException for a well-formed but bogus nextToken, got code={code!r}"
    )
    assert message == _BOGUS_TOKEN_MESSAGE, (
        f"expected message {_BOGUS_TOKEN_MESSAGE!r} for a bogus nextToken, got {message!r}"
    )

    # Positive control: the real token obtained above still works and advances to a
    # further, distinct page rather than repeating what maxResults=1 already returned.
    second_page = uxc.list_services(maxResults=1, nextToken=real_token)
    second_services = second_page["services"]
    assert len(second_services) >= 1, (
        f"expected the real nextToken to return >=1 further service, got {second_page!r}"
    )
    first_service = first_page["services"][0]
    assert second_services[0] != first_service, (
        f"real nextToken must advance past the first page's {first_service!r}, "
        f"but page 2 repeated it: {second_services!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected ValidationException for a well-formed but bogus nextToken; call SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

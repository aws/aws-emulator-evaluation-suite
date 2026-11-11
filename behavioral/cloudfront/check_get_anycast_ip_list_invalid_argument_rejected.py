"""get-anycast-ip-list-invalid-argument-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-anycast-ip-list-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAnycastIpList with a malformed Id fails InvalidArgument, distinct from
    EntityNotFound for a well-formed-looking but absent Id, while the list
    endpoint itself keeps working normally (positive control)."""
    cf = ctx.client("cloudfront")

    # Break #1: a grossly oversized Id (far longer than any real Anycast IP
    # list id, which is "aip_" followed by 22 alphanumerics) is rejected
    # outright -- distinct from a correctly shaped but nonexistent id, which
    # instead falls through to a real lookup and misses (EntityNotFound,
    # exercised below).
    #
    # ServiceUnavailable is not a modelled error for GetAnycastIpList (only
    # AccessDenied/EntityNotFound/InvalidArgument/UnsupportedOperation are).
    # Repeated back-to-back calls with this exact malformed Id can draw a
    # transient edge-side 503 -- edge-side throttling on request repetition,
    # not a property of the malformed Id itself, so it is retried rather
    # than asserted; the deterministic, modelled outcome is InvalidArgument.
    malformed_id = "A" * 512
    code_malformed, message_malformed = _error(
        lambda: cf.get_anycast_ip_list(Id=malformed_id),
        retry_on=("ServiceUnavailable",),
        max_attempts=3,
        interval_s=5.0,
    )
    assert code_malformed == "InvalidArgument", f"expected InvalidArgument, got {code_malformed!r}"
    invalid_message = "Id format is invalid"
    assert message_malformed == invalid_message, (
        f"expected message {invalid_message!r}, got {message_malformed!r}"
    )

    # Break #2: a well-formed id ("aip_" + 22 alphanumerics, the shape of a
    # real Anycast IP list id) that simply doesn't exist must be EntityNotFound
    # -- a different code from the malformed-argument case above.
    well_formed_absent_id = "aip_1A2B3C4D5E6F7G8H9J0K1L"
    code_absent, message_absent = _error(lambda: cf.get_anycast_ip_list(Id=well_formed_absent_id))
    assert code_absent == "EntityNotFound", f"expected EntityNotFound, got {code_absent!r}"
    not_found_message = "The specified Anycast IP list does not exist"
    assert message_absent == not_found_message, (
        f"expected message {not_found_message!r}, got {message_absent!r}"
    )
    assert code_absent != code_malformed, (
        f"expected distinct codes, both were {code_absent!r}"
    )

    # Positive control: the underlying API surface for this resource type is
    # healthy and a syntactically valid list call succeeds (whether or not any
    # Anycast IP lists exist in this account).
    resp = cf.list_anycast_ip_lists()
    assert "AnycastIpLists" in resp, f"missing AnycastIpLists in {resp!r}"
    items = resp["AnycastIpLists"]["Items"]
    assert isinstance(items, list), f"expected a list, got {items!r}"


def _error(fn, *, retry_on=(), max_attempts=1, interval_s=2.0) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    import time

    from botocore.exceptions import ClientError

    last_retried = None
    for attempt in range(max_attempts):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code in retry_on and attempt < max_attempts - 1:
                last_retried = code
                time.sleep(interval_s)
                continue
            return code, err.get("Message")
        else:
            raise AssertionError("expected a ClientError but the call succeeded")
    raise AssertionError(
        f"still hitting retryable error after {max_attempts} attempts: {last_retried!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

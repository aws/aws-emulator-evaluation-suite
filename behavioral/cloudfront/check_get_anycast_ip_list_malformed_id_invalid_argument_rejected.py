"""get-anycast-ip-list-malformed-id-invalid-argument-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-anycast-ip-list-malformed-id-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAnycastIpList returns EntityNotFound for a well-formed missing Id ("aip_" + 22
    alphanumerics) but InvalidArgument for an Id with unusual characters: shape is checked first."""
    cf = ctx.client("cloudfront")

    wellformed_missing_id = "aip_AAAAAAAAAAAAAAAAAAAAAA"
    not_found_message = "The specified Anycast IP list does not exist"
    c1, m1 = _error(lambda: cf.get_anycast_ip_list(Id=wellformed_missing_id))
    assert c1 == "EntityNotFound", c1
    assert m1 == not_found_message, f"expected message {not_found_message!r}, got {m1!r}"

    # Non-empty and of ordinary length: an empty Id is routed away from GetAnycastIpList entirely.
    weird_missing_id = "not-a-real-id-!!"
    c2, m2 = _error(lambda: cf.get_anycast_ip_list(Id=weird_missing_id))
    assert c2 == "InvalidArgument", c2
    invalid_message = "Id format is invalid"
    assert m2 == invalid_message, f"expected message {invalid_message!r}, got {m2!r}"

    # Positive control: creating a real list needs an approved Anycast quota, so a successful
    # list call shows the API itself is reachable.
    resp = cf.list_anycast_ip_lists()
    assert "AnycastIpLists" in resp
    assert isinstance(resp["AnycastIpLists"]["Items"], list)


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

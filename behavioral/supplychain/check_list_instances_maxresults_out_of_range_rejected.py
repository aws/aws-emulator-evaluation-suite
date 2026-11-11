"""list-instances-maxresults-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-instances-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListInstances with maxResults 21 or -1 fails server-side with ValidationException and the exact
    message (client-side validation is off), while a valid maxResults returns an instances list."""
    sc = ctx.client("supplychain", config=Config(parameter_validation=False))

    code_high, message_high = _error(lambda: sc.list_instances(maxResults=21))
    assert code_high == "ValidationException", f"expected ValidationException for maxResults=21, got {code_high}"
    expected_high = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 20"
    )
    assert message_high == expected_high, f"expected {expected_high!r}, got {message_high!r}"

    code_low, message_low = _error(lambda: sc.list_instances(maxResults=-1))
    assert code_low == "ValidationException", f"expected ValidationException for maxResults=-1, got {code_low}"
    expected_low = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message_low == expected_low, f"expected {expected_low!r}, got {message_low!r}"

    # positive control: a request within the documented range always succeeds, regardless of
    # how many (if any) instances exist on the account.
    ok = sc.list_instances(maxResults=5)
    assert "instances" in ok, f"expected an 'instances' key in the response, got {sorted(ok)}"


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because a target
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

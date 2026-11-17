"""list-key-value-stores-invalid-marker-rejected."""
from __future__ import annotations

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator accepting input real AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


CHECK = "list-key-value-stores-invalid-marker-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListKeyValueStores with a Marker outside its allowed character set is rejected
    with MalformedXML naming the pattern constraint, instead of being silently accepted."""
    cf = ctx.client("cloudfront")
    bad_marker = "not a valid marker !! ###"

    # Positive control: an ordinary call with no marker must succeed.
    control = cf.list_key_value_stores()
    assert "KeyValueStoreList" in control, (
        f"expected KeyValueStoreList in response, got keys={list(control)!r}"
    )

    code, message = _error(lambda: cf.list_key_value_stores(Marker=bad_marker))
    assert code == "MalformedXML", f"expected MalformedXML, got {code!r}: {message!r}"
    expected = (
        f"1 validation error detected: Value '{bad_marker}' at 'nextToken' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: [\w :+=./\\-]*"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

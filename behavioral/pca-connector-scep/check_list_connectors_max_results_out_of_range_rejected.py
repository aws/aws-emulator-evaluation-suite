"""list-connectors-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connectors-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-scep"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnectors rejects MaxResults 0 (sent with client-side validation off) and MaxResults 1001
    with ValidationException and the exact range message, while an in-range MaxResults is served."""
    scep = ctx.client("pca-connector-scep")
    scep_unvalidated = _unvalidated_client(ctx)

    too_low_code, too_low_message = _error(lambda: scep_unvalidated.list_connectors(MaxResults=0))
    assert too_low_code == "ValidationException", f"expected ValidationException for MaxResults=0, got {too_low_code!r}"
    expected = (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert too_low_message == expected, f"expected message {expected!r}, got {too_low_message!r}"

    too_high_code, too_high_message = _error(lambda: scep.list_connectors(MaxResults=1001))
    assert too_high_code == "ValidationException", f"expected ValidationException for MaxResults=1001, got {too_high_code!r}"
    expected = (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    )
    assert too_high_message == expected, f"expected message {expected!r}, got {too_high_message!r}"

    # Positive control: an in-range MaxResults must still be served successfully.
    resp = scep.list_connectors(MaxResults=5)
    assert "Connectors" in resp, f"expected a served response with Connectors, got {sorted(resp)!r}"


from botocore.exceptions import ClientError  # noqa: E402


def _unvalidated_client(ctx):
    """ctx's pca-connector-scep client with botocore's client-side parameter validation off, so
    the out-of-range MaxResults=0 reaches the wire instead of being rejected locally."""
    from botocore.config import Config

    return ctx.client("pca-connector-scep", config=Config(parameter_validation=False))


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

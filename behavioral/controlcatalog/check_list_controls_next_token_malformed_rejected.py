"""list-controls-next-token-malformed-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-controls-next-token-malformed-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_NEXT_TOKEN_MESSAGE = "The NextToken parameter is not valid or expired."


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListControls to reject the malformed NextToken, but it SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An opaque, non-decodable NextToken is rejected rather than silently treated as 'start from scratch'."""
    cc = ctx.client("controlcatalog")

    code, message = _error_code(
        lambda: cc.list_controls(MaxResults=5, NextToken="sim2real-garbage-not-a-real-token-000")
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed NextToken, got {code!r}"
    )
    assert message == _NEXT_TOKEN_MESSAGE, f"expected {_NEXT_TOKEN_MESSAGE!r}, got {message!r}"

    # Positive control: pagination with a real, freshly-issued token succeeds and genuinely
    # advances — proving the accept path isn't just "any request with a NextToken succeeds".
    first_page = cc.list_controls(MaxResults=5)
    real_token = first_page.get("NextToken")
    assert real_token, "expected a NextToken to exist for continued pagination"
    second_page = cc.list_controls(MaxResults=5, NextToken=real_token)
    second_controls = second_page.get("Controls")
    assert second_controls, (
        f"expected page 2 (fetched with a real NextToken) to return controls, got {second_controls!r}"
    )
    first_arns = {c["Arn"] for c in first_page["Controls"]}
    second_arns = {c["Arn"] for c in second_controls}
    overlap = first_arns & second_arns
    assert not overlap, (
        f"expected page 2 to advance past page 1 with a real NextToken, but both pages "
        f"contained {overlap}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

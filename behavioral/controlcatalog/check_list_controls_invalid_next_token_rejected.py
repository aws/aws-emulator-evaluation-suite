"""list-controls-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_NEXT_TOKEN_MESSAGE = "The NextToken parameter is not valid or expired."


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListControls rejects a syntactically-plausible but undecodable NextToken, while a real,
    freshly-issued NextToken is still honored for continuation — so the rejection is specific to
    the malformed token, not a wholesale refusal of pagination."""
    cc = ctx.client("controlcatalog")

    code, message = _error_code(lambda: cc.list_controls(NextToken="not-a-real-continuation-token"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == _NEXT_TOKEN_MESSAGE, f"expected {_NEXT_TOKEN_MESSAGE!r}, got {message!r}"

    # positive control: a real, freshly-issued NextToken is honored for continuation. This rules
    # out a target that rejects every NextToken (real or fake) rather than just malformed ones.
    first_page = cc.list_controls(MaxResults=1)
    assert len(first_page["Controls"]) == 1, (
        f"expected exactly 1 control in a MaxResults=1 page, got {len(first_page['Controls'])}"
    )
    real_token = first_page.get("NextToken")
    assert real_token, "expected a NextToken since the catalog has more than 1 control"
    second_page = cc.list_controls(MaxResults=1, NextToken=real_token)
    assert len(second_page["Controls"]) == 1, (
        f"continuation page did not return exactly 1 item, got {len(second_page['Controls'])}"
    )
    assert second_page["Controls"][0]["Arn"] != first_page["Controls"][0]["Arn"], (
        "continuation page repeated the first page's control instead of advancing"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListControls to reject the malformed NextToken, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

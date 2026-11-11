"""list-builds-malformed-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-builds-malformed-next-token-rejected"
GROUP = "validation"
SERVICES = ["codebuild"]


def _error(fn) -> tuple[str, str]:
    """Call fn() and return the ClientError (code, message). Raises if fn() unexpectedly
    succeeds, so a surprising accept can never masquerade as a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListBuilds refuses a malformed nextToken with InvalidInputException "Invalid continuation token
    specified.", while the same call without a token succeeds."""
    codebuild = ctx.client("codebuild")

    # Positive control first: an ordinary, token-less ListBuilds succeeds at the same moment,
    # so a later 400 cannot be explained by throttling or an outage.
    control = codebuild.list_builds()
    assert "ids" in control, f"control ListBuilds call did not return an 'ids' key: {control!r}"

    code, message = _error(lambda: codebuild.list_builds(nextToken="not-a-valid-pagination-token"))
    expected = "Invalid continuation token specified."
    assert (code, message) == ("InvalidInputException", expected), (
        f"expected InvalidInputException {expected!r}, got {code!r}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

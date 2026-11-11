"""list-extensions-malformed-token-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-extensions-malformed-token-rejected"
GROUP = "negative-classes"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListExtensions with a syntactically invalid pagination token is rejected with
    BadRequestException, never silently returning an empty or truncated page."""
    appconfig = ctx.client("appconfig")

    bad_token = "not-a-real-continuation-token"
    err = _error(lambda: appconfig.list_extensions(NextToken=bad_token))
    assert err["Code"] == "BadRequestException", (
        f"expected BadRequestException for a malformed NextToken, got {err['Code']!r}"
    )
    assert err["Message"] == f"Invalid nextToken parameter {bad_token}.", (
        f"unexpected message: {err['Message']!r}"
    )

    # Positive control in the same file: the same call without a token still succeeds.
    resp = appconfig.list_extensions()
    assert "Items" in resp, f"expected 'Items' in a successful ListExtensions response, got keys {list(resp)!r}"
    assert isinstance(resp["Items"], list), f"expected Items to be a list, got {type(resp['Items'])!r}"


def _error(fn: Callable[[], Any]) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this malformed NextToken, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

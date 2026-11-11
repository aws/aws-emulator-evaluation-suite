"""whitespace-access-token-unauthorized."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "whitespace-access-token-unauthorized"
GROUP = "error-semantics"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A whitespace-only access token is rejected with UnauthorizedException -- it is
    present and non-empty from the SDK's point of view, so the service itself (not client-side
    validation) must recognize it carries no real session identity."""
    sso = ctx.client("sso")

    code, message = _error(lambda: sso.list_accounts(accessToken="   "))
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code!r}"
    assert message == MESSAGE, f"expected {MESSAGE!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this bogus bearer token, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

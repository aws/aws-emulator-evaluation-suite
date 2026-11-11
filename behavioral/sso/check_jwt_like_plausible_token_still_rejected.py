"""jwt-like-plausible-token-still-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jwt-like-plausible-token-still-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A never-issued token shaped like a JWT (three dot-separated base64url segments) is rejected with
    UnauthorizedException and the exact message: the service verifies tokens, not their shape."""
    sso = ctx.client("sso")
    plausible_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJzaW0ycmVhbC1ib2d1cyIsImlhdCI6MTcwMDAwMDAwMH0."
        f"sim2real-{ctx.unique_name('sig')}"
    )

    code, message = _error(lambda: sso.list_accounts(accessToken=plausible_token))
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

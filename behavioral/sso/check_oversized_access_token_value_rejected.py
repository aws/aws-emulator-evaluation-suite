"""oversized-access-token-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oversized-access-token-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An oversized bearer-token value (the model sets no length limit) is rejected cleanly with
    UnauthorizedException and the exact message, not a crash, a hang or an acceptance."""
    sso = ctx.client("sso")
    oversized_token = "sim2real-bogus-" + ("a" * 8192)

    code, message = _error(lambda: sso.list_accounts(accessToken=oversized_token))
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

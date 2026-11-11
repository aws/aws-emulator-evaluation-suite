"""logout-repeated-calls-same-invalid-token-stay-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logout-repeated-calls-same-invalid-token-stay-rejected"
GROUP = "state"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Logout called twice with the same invalid bearer token is rejected both times with
    UnauthorizedException and the exact message: presenting a token again does not make it valid."""
    sso = ctx.client("sso")
    bogus_token = f"sim2real-bogus-{ctx.unique_name('tok')}"

    first_code, first_message = _error(lambda: sso.logout(accessToken=bogus_token))
    second_code, second_message = _error(lambda: sso.logout(accessToken=bogus_token))

    assert first_code == "UnauthorizedException", (
        f"first call: expected UnauthorizedException, got {first_code!r}"
    )
    assert first_message == MESSAGE, f"first call: expected {MESSAGE!r}, got {first_message!r}"
    assert second_code == "UnauthorizedException", (
        f"second call: expected UnauthorizedException, got {second_code!r} "
        "(a token that becomes valid, or an emulator that only rejects the first call, would "
        "surface here)"
    )
    assert second_message == MESSAGE, (
        f"second call: expected {MESSAGE!r}, got {second_message!r}"
    )


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

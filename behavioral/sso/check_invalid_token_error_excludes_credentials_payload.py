"""invalid-token-error-excludes-credentials-payload."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-token-error-excludes-credentials-payload"
GROUP = "error-semantics"
SERVICES = ["sso"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRoleCredentials with an invalid token is rejected with UnauthorizedException and the exact
    message, and the raw HTTP 401 body (captured before botocore drops unmodeled members) carries no
    roleCredentials payload."""
    sso = ctx.client("sso")
    bogus_token = f"sim2real-bogus-{ctx.unique_name('tok')}"

    captured: dict[str, object] = {}

    def _capture_raw(http_response, **_kwargs):
        captured["status"] = http_response.status_code
        captured["body"] = http_response.content

    sso.meta.events.register("after-call.sso.GetRoleCredentials", _capture_raw)

    try:
        sso.get_role_credentials(
            roleName="AdministratorAccess",
            accountId="111122223333",
            accessToken=bogus_token,
        )
        raise AssertionError("expected UnauthorizedException, call unexpectedly succeeded")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code!r}"
        message = err.response["Error"].get("Message")
        expected_message = "Session token not found or invalid"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
        assert "roleCredentials" not in err.response, (
            "error response must not include a roleCredentials payload"
        )

        assert "body" in captured, "after-call hook did not fire; no raw wire response captured"
        assert captured["status"] == 401, f"expected raw HTTP 401, got {captured['status']!r}"
        raw_body = json.loads(captured["body"])
        assert "roleCredentials" not in raw_body, (
            "raw wire body for the rejected call must not include a roleCredentials member -- "
            f"botocore already drops unmodeled fields from err.response, so the raw bytes are the "
            f"only place a fabricated payload could be caught; got {raw_body!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

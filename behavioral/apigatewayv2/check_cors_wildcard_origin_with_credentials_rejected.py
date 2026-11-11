"""cors-wildcard-origin-with-credentials-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-wildcard-origin-with-credentials-rejected"
GROUP = 'http-api'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises.
    Throttling is retried."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApi setting CORS AllowOrigins ["*"] with AllowCredentials=true is refused with
    BadRequestException, leaving the prior CORS config intact; "*" without credentials is accepted.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-cors.html
    """
    agw = ctx.client("apigatewayv2")
    good_origin = "https://ok.example.com"
    created = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"),
        ProtocolType="HTTP",
        Tags=TAGS,
        CorsConfiguration={
            "AllowOrigins": [good_origin],
            "AllowMethods": ["GET"],
            "AllowCredentials": True,
        },
    )
    api_id = created["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    cfg = agw.get_api(ApiId=api_id).get("CorsConfiguration") or {}
    assert cfg.get("AllowOrigins") == [good_origin], (
        f"setup: AllowOrigins should be [{good_origin!r}], got {cfg.get('AllowOrigins')}"
    )
    assert cfg.get("AllowCredentials") is True, (
        f"setup: AllowCredentials should round-trip as True, got {cfg.get('AllowCredentials')}"
    )

    code, message = _error_code(
        lambda: agw.update_api(
            ApiId=api_id,
            CorsConfiguration={
                "AllowOrigins": ["*"],
                "AllowMethods": ["GET"],
                "AllowCredentials": True,
            },
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for AllowOrigins=['*'] with AllowCredentials=true, "
        f"got {code} (None => the emulator accepted a configuration real AWS refuses)"
    )
    expected_message = "allow-credentials is not supported if 'allow-origin' is *"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    cfg = agw.get_api(ApiId=api_id).get("CorsConfiguration") or {}
    assert cfg.get("AllowOrigins") == [good_origin], (
        f"the rejected UpdateApi must not partially apply; AllowOrigins is now "
        f"{cfg.get('AllowOrigins')}"
    )
    assert cfg.get("AllowCredentials") is True, (
        f"the rejected UpdateApi must not partially apply; AllowCredentials is now "
        f"{cfg.get('AllowCredentials')}"
    )

    agw.update_api(
        ApiId=api_id,
        CorsConfiguration={
            "AllowOrigins": ["*"],
            "AllowMethods": ["GET"],
            "AllowCredentials": False,
        },
    )
    cfg = agw.get_api(ApiId=api_id).get("CorsConfiguration") or {}
    assert cfg.get("AllowOrigins") == ["*"], (
        f"control: the wildcard origin alone must be accepted, got {cfg.get('AllowOrigins')}"
    )
    assert cfg.get("AllowCredentials") is False, (
        f"control: AllowCredentials should now be False, got {cfg.get('AllowCredentials')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

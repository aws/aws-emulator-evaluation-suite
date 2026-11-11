"""bad-protocol-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bad-protocol-type-rejected"
GROUP = 'error-semantics'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApi with ProtocolType "FTP" (outside the WEBSOCKET|HTTP enum) fails BadRequestException
    and creates nothing (independent GetApis read); a valid CreateApi is the positive control."""
    agw = ctx.client("apigatewayv2")

    good = agw.create_api(Name=ctx.unique_name("sim2real-behav-goodproto-"), ProtocolType="HTTP", Tags=TAGS)
    good_id = good["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=good_id))
    assert good.get("ProtocolType") == "HTTP", f"positive control CreateApi: {good}"

    bad_name = ctx.unique_name("sim2real-behav-badproto-")
    try:
        created = agw.create_api(Name=bad_name, ProtocolType="FTP", Tags=TAGS)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code, message = error.get("Code"), error.get("Message")
    else:
        ctx.on_cleanup(lambda: agw.delete_api(ApiId=created["ApiId"]))
        raise AssertionError(
            f"expected CreateApi with ProtocolType='FTP' to be rejected, but it SUCCEEDED "
            f"and returned {created!r}"
        )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected_message = "Invalid protocol specified. Must be one of [HTTP, WEBSOCKET]"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    names = [api["Name"] for api in agw.get_apis().get("Items", [])]
    assert bad_name not in names, f"the rejected CreateApi must not appear in GetApis, got {names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""deep-cognito-idp-2-token-rotation-invalid-config-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-2-token-rotation-invalid-config-rejected"
GROUP = "refresh-token-rotation"
SERVICES = ["cognito-idp"]

EXPECTED_MESSAGE = (
    "ALLOW_REFRESH_TOKEN_AUTH is not a permitted ExplicitAuthFlow when refresh token rotation is enabled."
)


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """RefreshTokenRotation together with ALLOW_REFRESH_TOKEN_AUTH is refused with
    InvalidParameterException and the exact message on create and on update, while each alone is
    accepted and the refused update leaves the client's flows and rotation unchanged."""
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rot-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    rotation = {"Feature": "ENABLED", "RetryGracePeriodSeconds": 0}

    # The broken create: rotation + the legacy refresh flow.
    bad_name = ctx.unique_name("sim2real-behav-rot-bad-")
    code, message = _error(lambda: c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=bad_name,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        RefreshTokenRotation=rotation,
    ), on_success=lambda out: c.delete_user_pool_client(
        UserPoolId=pool_id, ClientId=out["UserPoolClient"]["ClientId"]))
    assert code == "InvalidParameterException", (
        f"rotation + ALLOW_REFRESH_TOKEN_AUTH on create returned {code!r} ({message!r})"
    )
    assert message == EXPECTED_MESSAGE, f"create rejection message was {message!r}"

    # Effect absent: no client by that name exists in this (our own) pool.
    names = [cl["ClientName"] for cl in _list_clients(c, pool_id)]
    assert bad_name not in names, f"the refused create left a client behind: {names!r}"

    # Positive controls: each half alone is legal.
    rot_client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-rot-ok-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"], RefreshTokenRotation=rotation,
    )["UserPoolClient"]
    rot_id = rot_client["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=rot_id))
    assert rot_client.get("RefreshTokenRotation") == rotation, (
        f"rotating client echoed {rot_client.get('RefreshTokenRotation')!r}"
    )

    legacy = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-rot-legacy-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    legacy_id = legacy["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=legacy_id))
    assert "ALLOW_REFRESH_TOKEN_AUTH" in legacy.get("ExplicitAuthFlows", []), (
        f"non-rotating client lost ALLOW_REFRESH_TOKEN_AUTH: {legacy.get('ExplicitAuthFlows')!r}"
    )

    before = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=rot_id)["UserPoolClient"]

    # The broken update: add the legacy flow to the rotating client.
    ucode, umessage = _error(lambda: c.update_user_pool_client(
        UserPoolId=pool_id, ClientId=rot_id,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        RefreshTokenRotation=rotation,
    ))
    assert ucode == "InvalidParameterException", (
        f"rotation + ALLOW_REFRESH_TOKEN_AUTH on update returned {ucode!r} ({umessage!r})"
    )
    assert umessage == EXPECTED_MESSAGE, f"update rejection message was {umessage!r}"

    after = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=rot_id)["UserPoolClient"]
    assert sorted(after.get("ExplicitAuthFlows", [])) == sorted(before.get("ExplicitAuthFlows", [])), (
        f"refused update changed ExplicitAuthFlows {before.get('ExplicitAuthFlows')!r} -> "
        f"{after.get('ExplicitAuthFlows')!r}"
    )
    assert "ALLOW_REFRESH_TOKEN_AUTH" not in after.get("ExplicitAuthFlows", []), (
        f"refused update still added the legacy flow: {after.get('ExplicitAuthFlows')!r}"
    )
    assert after.get("RefreshTokenRotation") == rotation, (
        f"refused update changed RefreshTokenRotation to {after.get('RefreshTokenRotation')!r}"
    )


def _list_clients(c, pool_id: str) -> list[dict]:
    out, token = [], None
    while True:
        kw = {"UserPoolId": pool_id, "MaxResults": 60}
        if token:
            kw["NextToken"] = token
        page = c.list_user_pool_clients(**kw)
        out.extend(page.get("UserPoolClients", []))
        token = page.get("NextToken")
        if not token:
            return out


def _error(fn, on_success=None) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises. An unexpected success is the finding:
    undo it (if told how) and raise rather than return a sentinel that reads like a code."""
    try:
        out = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    if on_success is not None:
        try:
            on_success(out)
        except Exception as exc:  # noqa: BLE001 - report the leak, keep the real finding
            print(f"could not undo unexpectedly accepted call: {exc!r}")
    raise AssertionError("call expected to be refused SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

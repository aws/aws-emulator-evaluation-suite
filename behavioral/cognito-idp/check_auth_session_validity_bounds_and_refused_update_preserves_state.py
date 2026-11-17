"""auth-session-validity-bounds-and-refused-update-preserves-state."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auth-session-validity-bounds-and-refused-update-preserves-state"
GROUP = "app-client-config"
SERVICES = ["cognito-idp"]

#: CreateUserPoolClient and UpdateUserPoolClient refuse AuthSessionValidity outside 3..15.
_EXCEEDS_MAX = (
    "InvalidParameterException",
    "1 validation error detected: Value '20' at 'authSessionValidity' failed to satisfy "
    "constraint: Member must have value less than or equal to 15",
)
_BELOW_MIN = (
    "InvalidParameterException",
    "1 validation error detected: Value '2' at 'authSessionValidity' failed to satisfy "
    "constraint: Member must have value greater than or equal to 3",
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises a ClientError carrying exactly ``code`` and ``message``."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, (
            f"expected error code {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused with {code}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient defaults AuthSessionValidity to 3 and accepts 3..15, refusing a value
    outside it with the bound's exact message; a refused UpdateUserPoolClient changes neither
    AuthSessionValidity nor ClientName, and one omitting the field keeps the stored value.
    """
    # Disabled so the below-minimum request reaches the service instead of being rejected by the
    # SDK's own client-side check, which only looks at the lower bound.
    idp = ctx.client("cognito-idp", config=Config(parameter_validation=False))

    pool_name = ctx.unique_name("sim2real-behav-cidp-asv-pool-")
    pool_id = idp.create_user_pool(PoolName=pool_name)["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: idp.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))

    # --- default
    default_name = ctx.unique_name("sim2real-behav-cidp-asv-default-")
    default_client = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=default_name)[
        "UserPoolClient"
    ]
    assert default_client["AuthSessionValidity"] == 3, (
        f"CreateUserPoolClient with AuthSessionValidity omitted returned "
        f"{default_client['AuthSessionValidity']!r}, expected the default 3"
    )
    described_default = idp.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=default_client["ClientId"]
    )["UserPoolClient"]
    assert described_default["AuthSessionValidity"] == 3, (
        f"DescribeUserPoolClient reported AuthSessionValidity "
        f"{described_default['AuthSessionValidity']!r} for a client created with it omitted, "
        f"expected the default 3"
    )

    # --- accepted bounds: the legal neighbours of the two refusals below
    min_name = ctx.unique_name("sim2real-behav-cidp-asv-min-")
    min_client = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=min_name, AuthSessionValidity=3
    )["UserPoolClient"]
    assert min_client["AuthSessionValidity"] == 3, (
        f"CreateUserPoolClient with AuthSessionValidity=3 returned "
        f"{min_client['AuthSessionValidity']!r}"
    )

    max_name = ctx.unique_name("sim2real-behav-cidp-asv-max-")
    max_client = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=max_name, AuthSessionValidity=15
    )["UserPoolClient"]
    assert max_client["AuthSessionValidity"] == 15, (
        f"CreateUserPoolClient with AuthSessionValidity=15 returned "
        f"{max_client['AuthSessionValidity']!r}"
    )

    # --- refused bounds on create
    over_name = ctx.unique_name("sim2real-behav-cidp-asv-over-")
    expect_error(
        lambda: idp.create_user_pool_client(
            UserPoolId=pool_id, ClientName=over_name, AuthSessionValidity=20
        ),
        *_EXCEEDS_MAX,
    )
    under_name = ctx.unique_name("sim2real-behav-cidp-asv-under-")
    expect_error(
        lambda: idp.create_user_pool_client(
            UserPoolId=pool_id, ClientName=under_name, AuthSessionValidity=2
        ),
        *_BELOW_MIN,
    )

    # --- a refused update changes neither AuthSessionValidity nor ClientName
    base_name = ctx.unique_name("sim2real-behav-cidp-asv-base-")
    base_client = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=base_name)[
        "UserPoolClient"
    ]
    base_client_id = base_client["ClientId"]
    assert base_client["AuthSessionValidity"] == 3, (
        f"baseline client was created with AuthSessionValidity "
        f"{base_client['AuthSessionValidity']!r}, expected the default 3"
    )

    rename_attempt = ctx.unique_name("sim2real-behav-cidp-asv-renamed-")
    expect_error(
        lambda: idp.update_user_pool_client(
            UserPoolId=pool_id,
            ClientId=base_client_id,
            ClientName=rename_attempt,
            AuthSessionValidity=20,
        ),
        *_EXCEEDS_MAX,
    )
    after_refusal = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=base_client_id)[
        "UserPoolClient"
    ]
    assert after_refusal["ClientName"] == base_name, (
        f"a refused UpdateUserPoolClient left ClientName as {after_refusal['ClientName']!r}, "
        f"expected the untouched {base_name!r}"
    )
    assert after_refusal["AuthSessionValidity"] == 3, (
        f"a refused UpdateUserPoolClient left AuthSessionValidity as "
        f"{after_refusal['AuthSessionValidity']!r}, expected the untouched 3"
    )

    # --- an update that omits AuthSessionValidity keeps the stored value
    rename_ok = ctx.unique_name("sim2real-behav-cidp-asv-renamed-ok-")
    updated = idp.update_user_pool_client(
        UserPoolId=pool_id, ClientId=base_client_id, ClientName=rename_ok
    )["UserPoolClient"]
    assert updated["ClientName"] == rename_ok, (
        f"UpdateUserPoolClient returned ClientName {updated['ClientName']!r}, expected {rename_ok!r}"
    )
    assert updated["AuthSessionValidity"] == 3, (
        f"UpdateUserPoolClient with AuthSessionValidity omitted returned "
        f"{updated['AuthSessionValidity']!r}, expected the previously stored 3"
    )
    after_omitted = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=base_client_id)[
        "UserPoolClient"
    ]
    assert after_omitted["AuthSessionValidity"] == 3, (
        f"DescribeUserPoolClient reported AuthSessionValidity "
        f"{after_omitted['AuthSessionValidity']!r} after an update that omitted it, expected the "
        f"previously stored 3"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

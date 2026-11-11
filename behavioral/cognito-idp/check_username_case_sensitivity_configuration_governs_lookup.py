"""username-case-sensitivity-configuration-governs-lookup."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "username-case-sensitivity-configuration-governs-lookup"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn) -> tuple[str, str]:
    """Run fn and return the AWS error (code, message) it raised. An unexpected SUCCESS raises,
    because a pool resolving a casing real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A case-insensitive pool stores the username lower-cased and resolves and signs in any casing to the
    one sub; a case-sensitive pool keeps the casing exactly and fails other casings with
    UserNotFoundException and "User does not exist." in AdminGetUser and sign-in."""
    c = ctx.client("cognito-idp")

    def _make_pool(case_sensitive: bool) -> tuple[str, str]:
        pid = c.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
            UsernameConfiguration={"CaseSensitive": case_sensitive},
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["UserPool"]["Id"]
        ctx.on_cleanup(lambda _id=pid: c.delete_user_pool(UserPoolId=_id))
        cid = c.create_user_pool_client(
            UserPoolId=pid,
            ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
            ExplicitAuthFlows=list(USER_AUTH_FLOWS),
            GenerateSecret=False,
            # LEGACY so a non-resolving username surfaces as UserNotFoundException rather than being
            # masked.
            PreventUserExistenceErrors="LEGACY",
        )["UserPoolClient"]["ClientId"]
        ctx.on_cleanup(
            lambda _p=pid, _c=cid: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
        )
        return pid, cid

    insensitive_pool, insensitive_client = _make_pool(False)
    sensitive_pool, sensitive_client = _make_pool(True)

    for pool_id, expected in ((insensitive_pool, False), (sensitive_pool, True)):
        got = c.describe_user_pool(UserPoolId=pool_id)["UserPool"].get(
            "UsernameConfiguration", {}
        )
        assert got.get("CaseSensitive") is expected, (
            f"DescribeUserPool must round-trip UsernameConfiguration.CaseSensitive={expected}, "
            f"got {got}"
        )

    stored = ctx.unique_name("sim2real-behav-cipuser") + "MiXeD"
    lowered = stored.lower()
    uppered = stored.upper()
    assert lowered != stored and uppered != stored, (
        f"test setup error: {stored} has no case variance"
    )

    def _seed(pool_id: str) -> str:
        """Create the mixed-case user; return the username the service echoed back."""
        created = c.admin_create_user(
            UserPoolId=pool_id, Username=stored, MessageAction="SUPPRESS"
        )["User"]["Username"]
        ctx.on_cleanup(
            lambda _p=pool_id: c.admin_delete_user(UserPoolId=_p, Username=stored)
        )
        c.admin_set_user_password(
            UserPoolId=pool_id, Username=stored, Password=PASSWORD, Permanent=True
        )
        return created

    insensitive_created = _seed(insensitive_pool)
    sensitive_created = _seed(sensitive_pool)

    # The canonicalisation happens at CREATE time and ONLY in the case-insensitive pool.
    # This is the difference an emulator that merely lower-cases at LOOKUP time misses:
    # it would keep reporting the mixed casing it was handed.
    assert insensitive_created == lowered, (
        f"a case-insensitive pool must lower-case the username on the way in, so "
        f"AdminCreateUser must echo {lowered}, got {insensitive_created}"
    )
    assert sensitive_created == stored, (
        f"a case-sensitive pool must store the submitted casing byte-exact, so "
        f"AdminCreateUser must echo {stored}, got {sensitive_created}"
    )

    def _sub(user) -> str:
        return next(a["Value"] for a in user["UserAttributes"] if a["Name"] == "sub")

    def _auth(client_id: str, username: str):
        return lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )

    # --- case-insensitive pool: every casing resolves to the ONE canonical identity ---
    subs = {}
    for label, name in (("stored", stored), ("lower", lowered), ("upper", uppered)):
        got = c.admin_get_user(UserPoolId=insensitive_pool, Username=name)
        assert got["Username"] == lowered, (
            f"a case-insensitive pool must resolve the {label} casing {name} and report "
            f"the canonical lower-cased username {lowered}, got {got['Username']}"
        )
        subs[label] = _sub(got)
    # The identity claim, pinned on `sub` rather than on the echoed username: three
    # casings must be ONE account. An emulator that creates a second user for a
    # different casing fails here even if it echoes usernames correctly.
    assert len(set(subs.values())) == 1, (
        f"all three casings must resolve to a single identity in a case-insensitive "
        f"pool; got distinct subs {subs}"
    )
    insensitive_listed = sorted(
        u["Username"] for u in c.list_users(UserPoolId=insensitive_pool)["Users"]
    )
    assert insensitive_listed == [lowered], (
        f"the case-insensitive pool must contain exactly one user, listed under the "
        f"canonical {lowered}, got {insensitive_listed}"
    )
    upper_result = _auth(insensitive_client, uppered)()["AuthenticationResult"]
    assert upper_result.get("AccessToken"), (
        f"a case-insensitive pool must authenticate {uppered} as {lowered}"
    )
    lower_result = _auth(insensitive_client, lowered)()["AuthenticationResult"]
    assert lower_result.get("AccessToken"), (
        f"a case-insensitive pool must authenticate the canonical {lowered}"
    )

    # --- case-sensitive pool: break exactly the casing ---
    lookup_code, lookup_message = _error(
        lambda: c.admin_get_user(UserPoolId=sensitive_pool, Username=lowered)
    )
    assert lookup_code == "UserNotFoundException", (
        f"a case-sensitive pool must not resolve {lowered} when {stored} was stored; expected "
        f"UserNotFoundException, got {lookup_code}"
    )
    assert lookup_message == "User does not exist.", (
        f"AdminGetUser({lowered}) UserNotFoundException message, got {lookup_message!r}"
    )
    auth_code, auth_message = _error(_auth(sensitive_client, lowered))
    assert auth_code == "UserNotFoundException", (
        f"a case-sensitive pool must reject a sign-in as {lowered}; expected "
        f"UserNotFoundException, got {auth_code}"
    )
    assert auth_message == "User does not exist.", (
        f"InitiateAuth({lowered}) UserNotFoundException message, got {auth_message!r}"
    )
    upper_auth_code, upper_auth_message = _error(_auth(sensitive_client, uppered))
    assert upper_auth_code == "UserNotFoundException", (
        f"a case-sensitive pool must reject a sign-in as {uppered}; expected "
        f"UserNotFoundException, got {upper_auth_code}"
    )
    assert upper_auth_message == "User does not exist.", (
        f"InitiateAuth({uppered}) UserNotFoundException message, got {upper_auth_message!r}"
    )

    # --- effect absent: the wrong-case attempts did not create a second identity ---
    users = c.list_users(UserPoolId=sensitive_pool)["Users"]
    names = sorted(u["Username"] for u in users)
    assert names == [stored], (
        f"the case-sensitive pool must still contain exactly [{stored}] after the rejected "
        f"lookups, got {names}"
    )

    # --- control: the exact stored casing works in the case-sensitive pool ---
    exact = c.admin_get_user(UserPoolId=sensitive_pool, Username=stored)
    assert exact["Username"] == stored, (
        f"AdminGetUser with the exact casing must resolve, got {exact['Username']}"
    )
    exact_result = _auth(sensitive_client, stored)()["AuthenticationResult"]
    assert exact_result.get("AccessToken"), (
        "the exact stored casing must authenticate in the case-sensitive pool"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

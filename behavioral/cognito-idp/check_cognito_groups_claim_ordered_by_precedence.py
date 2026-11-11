"""cognito-groups-claim-ordered-by-precedence."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "cognito-groups-claim-ordered-by-precedence"
GROUP = 'user-group-membership'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The cognito:groups claim lists the user's groups by ascending Precedence, not by membership
    order, identically in the IdToken and the AccessToken; consumers read the first entry as the
    effective group."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    username = ctx.unique_name("sim2real-behav-cipuser")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    # Precedence 1 < 5 < 10. Created and joined in a deliberately scrambled order so
    # insertion order can never coincide with precedence order.
    precedences = {"hi": 10, "lo": 1, "mid": 5}
    names: dict[str, str] = {}
    for label in ("hi", "lo", "mid"):
        group = ctx.unique_name(f"sim2real-behav-cip-{label}-")
        c.create_group(UserPoolId=pool_id, GroupName=group, Precedence=precedences[label])
        ctx.on_cleanup(
            lambda _p=pool_id, _g=group: c.delete_group(UserPoolId=_p, GroupName=_g)
        )
        names[label] = group

    for label in ("hi", "mid", "lo"):
        c.admin_add_user_to_group(
            UserPoolId=pool_id, Username=username, GroupName=names[label]
        )

    expected_order = [names["lo"], names["mid"], names["hi"]]

    result = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]

    claim_lists = {}
    for label, token in (("IdToken", result["IdToken"]), ("AccessToken", result["AccessToken"])):
        claims = _decode_jwt_segment(token.split(".")[1])
        groups = claims.get("cognito:groups")
        assert isinstance(groups, list), (
            f"{label} must carry a cognito:groups list claim, got {groups!r}"
        )
        assert sorted(groups) == sorted(expected_order), (
            f"{label} cognito:groups must contain exactly {sorted(expected_order)}, got "
            f"{sorted(groups)}"
        )
        assert groups == expected_order, (
            f"{label} cognito:groups must be ordered by ascending Precedence "
            f"{expected_order} (1, 5, 10), got {groups} — insertion order was "
            f"{[names['hi'], names['mid'], names['lo']]}"
        )
        claim_lists[label] = groups

    assert claim_lists["IdToken"] == claim_lists["AccessToken"], (
        f"the IdToken and AccessToken must agree on the cognito:groups ordering; got "
        f"{claim_lists['IdToken']} vs {claim_lists['AccessToken']}"
    )

    # The membership listing must agree on the set, so the ordering claim is not an artefact
    # of a different membership view.
    listed = {
        g["GroupName"]: g
        for g in c.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    }
    assert sorted(listed) == sorted(expected_order), (
        f"AdminListGroupsForUser must report exactly {sorted(expected_order)}, got "
        f"{sorted(listed)}"
    )
    for label, group in names.items():
        assert listed[group].get("Precedence") == precedences[label], (
            f"AdminListGroupsForUser must report Precedence {precedences[label]} for {group}, "
            f"got {listed[group].get('Precedence')}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

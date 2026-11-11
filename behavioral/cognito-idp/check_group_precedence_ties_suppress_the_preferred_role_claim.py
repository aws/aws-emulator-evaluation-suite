"""group-precedence-ties-suppress-the-preferred-role-claim."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "group-precedence-ties-suppress-the-preferred-role-claim"
GROUP = "user-group-membership"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
#: Group configuration reaches token minting asynchronously; every wait below is a bounded
#: retry over a FRESH sign-in and raises on timeout.
_PROPAGATION_DEADLINE_S = 90.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """cognito:preferred_role is the role of the single lowest-Precedence group and is absent when
    two groups tie at the lowest Precedence with different roles; cognito:roles lists both roles.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html
    """
    c = ctx.client("cognito-idp")
    role_a = _create_role(ctx, "cognito-identity.amazonaws.com")
    role_b = _create_role(ctx, "cognito-identity.amazonaws.com")
    assert role_a["arn"] != role_b["arn"], (
        f"the two roles must be distinct for the tie to be a tie, both were {role_a['arn']}"
    )

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS), GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    # The pool starts in the TIED state, so no earlier single-winner state exists that a stale
    # token could still be carrying — the absence below cannot be an artefact of ordering.
    group_a = ctx.unique_name("sim2real-behav-cip-ga-")
    group_b = ctx.unique_name("sim2real-behav-cip-gb-")
    for name, role in ((group_a, role_a), (group_b, role_b)):
        c.create_group(UserPoolId=pool_id, GroupName=name, Precedence=1, RoleArn=role["arn"])
        ctx.on_cleanup(
            lambda _p=pool_id, _g=name: c.delete_group(UserPoolId=_p, GroupName=_g)
        )
        c.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=name)

    listed = {
        g["GroupName"]: g
        for g in c.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]
    }
    assert set(listed) == {group_a, group_b}, (
        f"AdminListGroupsForUser must report exactly {sorted((group_a, group_b))}, got "
        f"{sorted(listed)}"
    )
    assert listed[group_a].get("RoleArn") == role_a["arn"], (
        f"group {group_a} must carry RoleArn {role_a['arn']}, got "
        f"{listed[group_a].get('RoleArn')!r}"
    )
    assert listed[group_b].get("RoleArn") == role_b["arn"], (
        f"group {group_b} must carry RoleArn {role_b['arn']}, got "
        f"{listed[group_b].get('RoleArn')!r}"
    )

    both = {role_a["arn"], role_b["arn"]}

    # --- the tie: the control (both roles present) and the assertion (no winner) are read from
    # the SAME token, so the absence is bounded by a demonstrated positive rather than a wait.
    tied, tie_latency = _poll_id_claims(
        c, client_id, username,
        lambda claims: set(claims.get("cognito:roles") or []) == both,
        description=f"cognito:roles naming both {sorted(both)}",
    )
    assert "cognito:preferred_role" not in tied, (
        f"two groups tied at Precedence 1 with different role ARNs must leave "
        f"cognito:preferred_role unset; the token that already lists both roles claims "
        f"{tied.get('cognito:preferred_role')!r}"
    )
    # It must not appear late either: consecutive fresh sign-ins over at least three times the
    # measured propagation latency must all agree, and all must still list both roles.
    hold_s = max(3 * tie_latency, 10.0)
    hold_started = time.monotonic()
    samples = 0
    while time.monotonic() - hold_started < hold_s:
        claims = _id_claims(c, client_id, username)
        samples += 1
        assert set(claims.get("cognito:roles") or []) == both, (
            f"a sign-in during the tie window stopped listing both roles, so the window is not "
            f"measuring the tie: cognito:roles={claims.get('cognito:roles')!r}"
        )
        assert "cognito:preferred_role" not in claims, (
            f"cognito:preferred_role appeared {time.monotonic() - hold_started:.1f}s into the "
            f"tie window with value {claims.get('cognito:preferred_role')!r}"
        )
        time.sleep(2.0)
    assert samples >= 2, (
        f"the tie window took only {samples} sample(s) over {hold_s:.1f}s, too few to claim the "
        f"claim never appears"
    )

    # --- repair: breaking the tie must MAKE the withheld claim appear, naming the lower group ---
    # UpdateGroup re-sends both RoleArn and Precedence so an omitted field cannot be reset.
    c.update_group(
        UserPoolId=pool_id, GroupName=group_b, Precedence=5, RoleArn=role_b["arn"],
    )
    resolved, _ = _poll_id_claims(
        c, client_id, username,
        lambda claims: claims.get("cognito:preferred_role") == role_a["arn"],
        description=(
            f"cognito:preferred_role becoming {role_a['arn']} once {group_b} moved to "
            f"Precedence 5"
        ),
    )
    assert set(resolved.get("cognito:roles") or []) == both, (
        f"breaking the tie must not drop a role from cognito:roles; expected {sorted(both)}, got "
        f"{resolved.get('cognito:roles')!r}"
    )

    # --- and it tracks Precedence, not creation order: swap the two and the winner swaps ---
    c.update_group(
        UserPoolId=pool_id, GroupName=group_a, Precedence=5, RoleArn=role_a["arn"],
    )
    c.update_group(
        UserPoolId=pool_id, GroupName=group_b, Precedence=1, RoleArn=role_b["arn"],
    )
    swapped, _ = _poll_id_claims(
        c, client_id, username,
        lambda claims: claims.get("cognito:preferred_role") == role_b["arn"],
        description=(
            f"cognito:preferred_role following Precedence to {role_b['arn']} after the swap"
        ),
    )
    assert set(swapped.get("cognito:roles") or []) == both, (
        f"the swap must not drop a role from cognito:roles; expected {sorted(both)}, got "
        f"{swapped.get('cognito:roles')!r}"
    )


def _id_claims(c, client_id: str, username: str) -> dict:
    """Sign in afresh and return the ID token's claims. Claims are computed at authentication
    time, so every observation needs its own sign-in."""
    token = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["IdToken"]
    parts = token.split(".")
    assert len(parts) == 3, f"the IdToken is not a well-formed JWT: {token[:24]!r}..."
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))


def _poll_id_claims(c, client_id: str, username: str, predicate, *, description: str,
                    timeout_s: float = _PROPAGATION_DEADLINE_S,
                    interval_s: float = 3.0) -> tuple[dict, float]:
    """Re-authenticate until predicate(id_claims) holds; return (claims, seconds waited).

    Raises on timeout — a group-configuration change that never reaches the token is the defect,
    not a slow environment, and returning the last value would let it pass."""
    started = time.monotonic()
    deadline = started + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _id_claims(c, client_id, username)
        if predicate(last):
            return last, time.monotonic() - started
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} was never observed within {timeout_s}s; last ID token claims were "
        f"{last!r}"
    )


def _create_role(ctx, trust_service: str) -> dict[str, str]:
    """Create an IAM role for a Cognito group to carry; it is never assumed, only a claim value.

    CreateRole needs a Condition block for a cognito-identity principal; the aud is a placeholder.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cip-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": trust_service},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {f"{trust_service}:aud": ctx.unique_name("sim2real-behav-cip-aud-")},
                "ForAnyValue:StringLike": {f"{trust_service}:amr": "authenticated"},
            },
        }],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    ctx.on_cleanup(lambda _r=role_name: _delete_role(ctx, _r))
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """Remove the role's attached and inline policies, then delete it."""
    _leaks: list = []
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        except ClientError as e:
            teardown_code = e.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("NoSuchEntity",):
                _leaks.append(
                    (f"could not detach {p['PolicyArn']} from {role_name}: {e!r}", e)
                )
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        except ClientError as e:
            teardown_code = e.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("NoSuchEntity",):
                _leaks.append(
                    (f"could not delete inline policy {pname} on {role_name}: {e!r}", e)
                )
    iam.delete_role(RoleName=role_name)
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

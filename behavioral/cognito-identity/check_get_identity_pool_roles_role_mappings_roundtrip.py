"""get-identity-pool-roles-role-mappings-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-identity-pool-roles-role-mappings-roundtrip"
GROUP = "state"
SERVICES = ["cognito-identity"]


def _poll_until(probe, predicate, *, timeout_s=20.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError:
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles with RoleMappings against a configured provider round-trips via GetIdentityPoolRoles."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-cog-rolemap-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"],
        lambda arn: arn == role_arn,
    )

    # "Token" role-mapping type resolves roles from cognito:roles/cognito:preferred_role claims,
    # which only Cognito user pools and OpenID Connect providers place in their tokens. Facebook
    # (a classic SupportedLoginProviders entry) never supplies such claims, and real AWS rejects
    # a Token-type mapping for it at SetIdentityPoolRoles time with a persistent (non-transient)
    # error. "Rules" mappings, by contrast, are provider-agnostic (they
    # just compare claim strings) and are valid for any configured login provider, so use that
    # type here; only IAM role-ARN visibility remains genuinely eventually consistent.
    role_mappings = {
        "graph.facebook.com": {
            "Type": "Rules",
            "AmbiguousRoleResolution": "AuthenticatedRole",
            "RulesConfiguration": {
                "Rules": [
                    {
                        "Claim": "isPaidUser",
                        "MatchType": "Equals",
                        "Value": "true",
                        "RoleARN": role_arn,
                    }
                ]
            },
        }
    }

    def _set_roles():
        try:
            ci.set_identity_pool_roles(
                IdentityPoolId=pool_id,
                Roles={"authenticated": role_arn, "unauthenticated": role_arn},
                RoleMappings=role_mappings,
            )
            return True
        except ClientError:
            # The IAM role just created above may not yet be visible/assumable from
            # cognito-identity's perspective; SetIdentityPoolRoles can transiently reject the
            # role ARN until IAM's eventual-consistency window closes. Swallow and retry via
            # the caller's bounded poll rather than failing on the first attempt.
            return False

    set_ok = _poll_until(_set_roles, lambda ok: ok is True, timeout_s=60.0, interval_s=3.0)
    assert set_ok is True, "SetIdentityPoolRoles never succeeded (IAM role may not have propagated)"

    # SetIdentityPoolRoles is eventually consistent on real AWS: the very next GetIdentityPoolRoles
    # call can transiently omit "Roles"/return stale RoleMappings before propagation completes, so
    # poll for the readback to reflect what was just set instead of asserting on the first read.
    readback = _poll_until(
        lambda: ci.get_identity_pool_roles(IdentityPoolId=pool_id),
        lambda resp: resp is not None
        and resp.get("Roles", {}).get("authenticated") == role_arn
        and resp.get("Roles", {}).get("unauthenticated") == role_arn
        and resp.get("RoleMappings") == role_mappings,
    )
    assert readback is not None, "GetIdentityPoolRoles never returned a response"
    assert "Roles" in readback and readback["Roles"], (
        f"GetIdentityPoolRoles never reflected the roles just set: {readback}"
    )
    assert readback["Roles"]["authenticated"] == role_arn, (
        f"expected authenticated role {role_arn}, got {readback['Roles'].get('authenticated')}"
    )
    assert readback["Roles"]["unauthenticated"] == role_arn, (
        f"expected unauthenticated role {role_arn}, got {readback['Roles'].get('unauthenticated')}"
    )
    assert readback["RoleMappings"] == role_mappings, (
        f"expected RoleMappings {role_mappings}, got {readback.get('RoleMappings')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""get-identity-pool-roles-rules-configuration-structure-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-identity-pool-roles-rules-configuration-structure-preserved"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIdentityPoolRoles returns the exact nested RulesConfiguration.Rules array
    (order, Claim, MatchType, Value, RoleARN) after a rule-based SetIdentityPoolRoles,
    verifying nested-object data-plane fidelity."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "sim2real-fake-app-id"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # SetIdentityPoolRoles does not need real IAM roles to exist -- it stores the
    # supplied ARN strings verbatim for later use by GetCredentialsForIdentity.
    # However AWS DOES require the ARN's account to match the caller's account
    # (Cross-account pass role is rejected), so we build ARNs against the real
    # caller account rather than a placeholder.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    auth_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-auth-role"
    unauth_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-unauth-role"
    admin_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-admin-role"


    rules = [
        {"Claim": "custom:department", "MatchType": "Equals", "Value": "engineering", "RoleARN": auth_role_arn},
        {"Claim": "custom:level", "MatchType": "Contains", "Value": "admin", "RoleARN": admin_role_arn},
        {"Claim": "custom:region", "MatchType": "NotEqual", "Value": "restricted", "RoleARN": unauth_role_arn},
    ]
    role_mappings = {
        "graph.facebook.com": {
            "Type": "Rules",
            "AmbiguousRoleResolution": "AuthenticatedRole",
            "RulesConfiguration": {"Rules": rules},
        }
    }
    roles = {"authenticated": auth_role_arn, "unauthenticated": unauth_role_arn}

    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles, RoleMappings=role_mappings)

    got = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert got["Roles"] == roles, f"Roles mismatch: {got['Roles']!r} != {roles!r}"

    got_mapping = got["RoleMappings"]["graph.facebook.com"]
    assert got_mapping["Type"] == "Rules", f"Type mismatch: {got_mapping['Type']!r} != 'Rules'"
    assert got_mapping["AmbiguousRoleResolution"] == "AuthenticatedRole", (
        f"AmbiguousRoleResolution mismatch: {got_mapping['AmbiguousRoleResolution']!r} != 'AuthenticatedRole'"
    )
    got_rules = got_mapping["RulesConfiguration"]["Rules"]
    assert got_rules == rules, f"Rules array mismatch (order/content): {got_rules!r} != {rules!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

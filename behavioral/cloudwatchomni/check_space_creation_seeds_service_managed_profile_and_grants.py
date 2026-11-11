"""space-creation-seeds-service-managed-profile-and-grants."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "space-creation-seeds-service-managed-profile-and-grants"
GROUP = "spaces"
SERVICES = ["cloudwatchomni"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})


def _domain(ctx, cwo) -> dict:
    domain = cwo.create_domain(
        name=ctx.unique_name("sim2real-behav-cwo-dom-"), identityProviders=["IAM"]
    )["domain"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_domain(domainId=domain["domainId"]),
                             "ResourceNotFoundException"))
    return domain


def _space(ctx, cwo, domain_id: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cwo-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    space = cwo.create_space(
        name=ctx.unique_name("sim2real-behav-cwo-space-"), domainId=domain_id, dataAccessRoleArn=role_arn
    )["space"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_space(spaceId=space["spaceId"]),
                             "ResourceNotFoundException", "AccessDeniedException"))
    return space


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """A new space holds one service-managed access profile and two service-managed grants: a
    SPACE_ADMIN grant and an AGENT grant whose principal is derived from the space id.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space = _space(ctx, cwo, domain_id)
    space_id = space["spaceId"]
    assert space["encryptionConfiguration"] == {"encryptionStrategy": "AWS_OWNED"}, (
        f"expected AWS_OWNED encryption by default, got {space.get('encryptionConfiguration')!r}"
    )
    assert space["status"] == "ACTIVE", f"expected ACTIVE, got {space['status']!r}"

    profiles = [p for page in cwo.get_paginator("list_access_profiles").paginate(spaceId=space_id)
                for p in page["items"]]
    assert [(p["name"], p["profileType"]) for p in profiles] == [
        ("DefaultAccessProfileForAsyncWorkflows", "SERVICE_MANAGED")
    ], f"unexpected seeded profiles {[(p['name'], p.get('profileType')) for p in profiles]!r}"

    grants = {g["name"]: g for page in cwo.get_paginator("list_access_grants").paginate(spaceId=space_id)
              for g in page["items"]}
    assert sorted(grants) == ["OmniDefaults-AsyncAccessProfile-AgentCanAssume", "OmniDefaults-Space-Admin"], (
        f"unexpected seeded grants {sorted(grants)!r}"
    )
    admin = grants["OmniDefaults-Space-Admin"]
    assert (admin["permission"], admin["grantType"]) == ("SPACE_ADMIN", "SERVICE_MANAGED"), (
        f"unexpected admin grant {admin['permission']!r}/{admin['grantType']!r}"
    )
    agent = grants["OmniDefaults-AsyncAccessProfile-AgentCanAssume"]
    assert (agent["permission"], agent["grantType"]) == ("CUSTOM", "SERVICE_MANAGED"), (
        f"unexpected agent grant {agent['permission']!r}/{agent['grantType']!r}"
    )
    assert agent["principal"]["principalType"] == "AGENT", f"unexpected {agent['principal']['principalType']!r}"
    assert agent["principal"]["principalId"] == f"agent-{space_id}", "the agent principal must name the space"
    assert {g["domainId"] for g in grants.values()} == {domain_id}, "every seeded grant must name the domain"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

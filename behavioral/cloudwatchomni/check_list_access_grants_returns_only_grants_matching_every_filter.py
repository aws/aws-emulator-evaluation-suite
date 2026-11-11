"""list-access-grants-returns-only-grants-matching-every-filter."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-access-grants-returns-only-grants-matching-every-filter"
GROUP = "access-control"
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """ListAccessGrants scoped to a space returns a grant only when it matches every filter given:
    permission, principal type and principal id each narrow the result, and together intersect.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]
    pids = []
    for _ in range(2):
        pid = cwo.create_access_profile(
            spaceId=space_id, name=ctx.unique_name("sim2real-behav-cwo-prof-"))["accessProfile"]["profileId"]
        ctx.on_cleanup(_teardown(lambda p=pid: cwo.delete_access_profile(spaceId=space_id, profileId=p),
                                 "ResourceNotFoundException"))
        pids.append(pid)
    made = {}
    for pid, permission in ((pids[0], "READ"), (pids[0], "READ_WRITE_DELETE"), (pids[1], "READ")):
        gid = cwo.create_access_grant(
            domainId=domain_id, spaceId=space_id, name=ctx.unique_name("sim2real-behav-cwo-grant-"),
            principal={"principalType": "ACCESS_PROFILE", "principalId": pid}, permission=permission,
        )["accessGrant"]["grantId"]
        ctx.on_cleanup(_teardown(lambda g=gid: cwo.delete_access_grant(grantId=g), "ResourceNotFoundException"))
        made[gid] = (pid, permission)


    def ids(**filters):
        return {g["grantId"] for page in cwo.get_paginator("list_access_grants").paginate(spaceId=space_id, **filters)
                for g in page["items"]}


    def expect(pred):
        return {gid for gid, row in made.items() if pred(*row)}


    got = ids(principalType="ACCESS_PROFILE")
    assert got == set(made), f"principalType=ACCESS_PROFILE returned {len(got)} grant(s), expected the 3 made"
    got = ids(permission="READ")
    assert got == expect(lambda p, perm: perm == "READ"), f"permission=READ returned {len(got)} grant(s)"
    got = ids(principalId=pids[0])
    assert got == expect(lambda p, perm: p == pids[0]), f"principalId filter returned {len(got)} grant(s)"
    got = ids(principalId=pids[0], permission="READ")
    assert got == expect(lambda p, perm: p == pids[0] and perm == "READ"), f"combined filters returned {len(got)}"
    assert ids(principalId=pids[1], permission="READ_WRITE_DELETE") == set(), "a filter no grant matches must be empty"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

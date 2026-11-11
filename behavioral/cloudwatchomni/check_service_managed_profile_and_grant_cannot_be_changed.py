"""service-managed-profile-and-grant-cannot-be-changed."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-managed-profile-and-grant-cannot-be-changed"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """The service-managed access profile refuses update and delete and the service-managed grants
    refuse delete, each as a conflict, and all of them stay in the space.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]
    profile = next(p for p in cwo.list_access_profiles(spaceId=space_id)["items"]
                   if p["profileType"] == "SERVICE_MANAGED")
    grant_ids = sorted(g["grantId"] for g in cwo.list_access_grants(spaceId=space_id)["items"]
                       if g["grantType"] == "SERVICE_MANAGED")
    assert len(grant_ids) == 2, f"expected two service-managed grants, got {len(grant_ids)}"

    code, message = _error(lambda: cwo.update_access_profile(
        spaceId=space_id, profileId=profile["profileId"], description="changed"))
    assert (code, message) == ("ConflictException", "A system-managed access profile cannot be updated"), (
        f"unexpected answer to an update: {code}: {message!r}"
    )
    code, message = _error(lambda: cwo.delete_access_profile(spaceId=space_id, profileId=profile["profileId"]))
    assert (code, message) == ("ConflictException", "A system-managed access profile cannot be deleted"), (
        f"unexpected answer to a profile delete: {code}: {message!r}"
    )
    for grant_id in grant_ids:
        code, message = _error(lambda g=grant_id: cwo.delete_access_grant(grantId=g))
        assert (code, message) == ("ConflictException", "A system-managed grant cannot be deleted"), (
            f"unexpected answer to a grant delete: {code}: {message!r}"
        )

    kept = cwo.get_access_profile(spaceId=space_id, profileId=profile["profileId"])["accessProfile"]
    assert kept.get("description") == profile.get("description"), "the refused update changed the profile"
    still = sorted(g["grantId"] for g in cwo.list_access_grants(spaceId=space_id)["items"]
                   if g["grantType"] == "SERVICE_MANAGED")
    assert still == grant_ids, "the refused deletes must keep both grants"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

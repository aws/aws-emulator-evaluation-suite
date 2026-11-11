"""deleting-an-access-profile-removes-the-grants-naming-it."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleting-an-access-profile-removes-the-grants-naming-it"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """DeleteAccessProfile succeeds while a grant names the profile as its principal, and the grant
    is then not found, while a grant naming another profile is untouched.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]
    profiles, grants = [], []
    for _ in range(2):
        pid = cwo.create_access_profile(
            spaceId=space_id, name=ctx.unique_name("sim2real-behav-cwo-prof-"))["accessProfile"]["profileId"]
        ctx.on_cleanup(_teardown(lambda p=pid: cwo.delete_access_profile(spaceId=space_id, profileId=p),
                                 "ResourceNotFoundException"))
        gid = cwo.create_access_grant(
            domainId=domain_id, spaceId=space_id, name=ctx.unique_name("sim2real-behav-cwo-grant-"),
            principal={"principalType": "ACCESS_PROFILE", "principalId": pid}, permission="READ",
        )["accessGrant"]["grantId"]
        ctx.on_cleanup(_teardown(lambda g=gid: cwo.delete_access_grant(grantId=g), "ResourceNotFoundException"))
        profiles.append(pid)
        grants.append(gid)

    cwo.delete_access_profile(spaceId=space_id, profileId=profiles[0])
    code, message = _error(lambda: cwo.get_access_profile(spaceId=space_id, profileId=profiles[0]))
    assert (code, message) == ("ResourceNotFoundException", "Access profile not found"), (
        f"expected the profile gone, got {code}: {message!r}"
    )
    code, message = _error(lambda: cwo.get_access_grant(grantId=grants[0]))
    assert (code, message) == ("ResourceNotFoundException", "AccessGrant not found"), (
        f"expected the grant naming the deleted profile gone, got {code}: {message!r}"
    )
    other = cwo.get_access_grant(grantId=grants[1])["accessGrant"]
    assert other["principal"]["principalId"] == profiles[1], "the other profile's grant must be untouched"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

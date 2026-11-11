"""access-profile-name-is-unique-within-a-space."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-profile-name-is-unique-within-a-space"
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
    """A second access profile under a taken name is refused as a conflict; renaming the first
    frees the name for a new profile, and a description-only update keeps the new name.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]
    name = ctx.unique_name("sim2real-behav-cwo-prof-")
    first = cwo.create_access_profile(spaceId=space_id, name=name, description="first")["accessProfile"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_access_profile(spaceId=space_id, profileId=first["profileId"]),
                             "ResourceNotFoundException"))

    code, message = _error(lambda: cwo.create_access_profile(spaceId=space_id, name=name))
    assert (code, message) == ("ConflictException", "An access profile with that name already exists in this space"), (
        f"unexpected answer to a duplicate profile name: {code}: {message!r}"
    )

    renamed = ctx.unique_name("sim2real-behav-cwo-prof-")
    cwo.update_access_profile(spaceId=space_id, profileId=first["profileId"], name=renamed)
    cwo.update_access_profile(spaceId=space_id, profileId=first["profileId"], description="second")
    got = cwo.get_access_profile(spaceId=space_id, profileId=first["profileId"])["accessProfile"]
    assert (got["name"], got.get("description")) == (renamed, "second"), (
        f"expected ({renamed!r}, 'second'), got ({got['name']!r}, {got.get('description')!r})"
    )
    assert got["profileType"] == "CUSTOMER_MANAGED", f"expected CUSTOMER_MANAGED, got {got.get('profileType')!r}"

    reused = cwo.create_access_profile(spaceId=space_id, name=name)["accessProfile"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_access_profile(spaceId=space_id, profileId=reused["profileId"]),
                             "ResourceNotFoundException"))
    assert reused["profileId"] != first["profileId"], "the freed name must mint a new profile"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

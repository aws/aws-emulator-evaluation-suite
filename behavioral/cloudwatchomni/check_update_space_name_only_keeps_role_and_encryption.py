"""update-space-name-only-keeps-role-and-encryption."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-space-name-only-keeps-role-and-encryption"
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
    """UpdateSpace with only a new name renames the space and leaves its data access role,
    encryption, domain and ARN as they were, as GetSpace and ListSpaces both show.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space = _space(ctx, cwo, domain_id)
    new_name = ctx.unique_name("sim2real-behav-cwo-space-")
    cwo.update_space(spaceId=space["spaceId"], name=new_name)

    got = cwo.get_space(spaceId=space["spaceId"])["space"]
    assert got["name"] == new_name, f"expected {new_name!r}, got {got['name']!r}"
    for key in ("dataAccessRoleArn", "encryptionConfiguration", "domainArn", "spaceArn", "createdAt"):
        assert got.get(key) == space.get(key), f"{key} changed on a name-only update"
    listed = {s["spaceId"]: s["name"] for page in cwo.get_paginator("list_spaces").paginate(domainId=domain_id)
              for s in page["items"]}
    assert listed.get(space["spaceId"]) == new_name, f"ListSpaces shows {listed.get(space['spaceId'])!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

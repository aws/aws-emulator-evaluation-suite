"""domain-with-a-space-cannot-be-deleted."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-with-a-space-cannot-be-deleted"
GROUP = "domains"
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
    """DeleteDomain is refused while the domain holds a space, naming the domain and the count,
    and the domain stays readable; after DeleteSpace the domain deletes.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    space_id = _space(ctx, cwo, domain_id)["spaceId"]

    code, message = _error(lambda: cwo.delete_domain(domainId=domain_id))
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == (
        f"Cannot delete Domain {domain_id} because it has 1 associated Spaces. Delete all Spaces first."
    ), f"unexpected message {message!r}"
    assert cwo.get_domain(domainId=domain_id)["domain"]["status"] == "ACTIVE", "the refused delete must keep the domain"

    cwo.delete_space(spaceId=space_id)
    cwo.delete_domain(domainId=domain_id)
    code, message = _error(lambda: cwo.get_domain(domainId=domain_id))
    assert (code, message) == ("ResourceNotFoundException", "Domain not found"), (
        f"expected the domain gone once its space was deleted, got {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""account-holds-at-most-one-domain."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-holds-at-most-one-domain"
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
    """While an account-scoped domain exists a second CreateDomain is refused as a conflict and
    ListDomains still shows the one domain; once it is deleted a new domain may be created.
    """
    cwo = ctx.client("cloudwatchomni")
    first = _domain(ctx, cwo)
    second_name = ctx.unique_name("sim2real-behav-cwo-dom-")
    code, message = _error(lambda: cwo.create_domain(name=second_name, identityProviders=["IAM"]))
    assert (code, message) == ("ConflictException", "A domain already exists for this account"), (
        f"unexpected answer to a second domain: {code}: {message!r}"
    )
    ids = [d["domainId"] for d in cwo.list_domains()["items"]]
    assert ids == [first["domainId"]], f"expected only the first domain listed, got {len(ids)} domain(s)"

    cwo.delete_domain(domainId=first["domainId"])
    code, message = _error(lambda: cwo.get_domain(domainId=first["domainId"]))
    assert (code, message) == ("ResourceNotFoundException", "Domain not found"), (
        f"expected the deleted domain to be gone, got {code}: {message!r}"
    )
    replacement = cwo.create_domain(name=second_name, identityProviders=["IAM"])["domain"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_domain(domainId=replacement["domainId"]),
                             "ResourceNotFoundException"))
    assert replacement["domainId"] != first["domainId"], "expected a fresh domain id"
    assert replacement["name"] == second_name, f"expected {second_name!r}, got {replacement.get('name')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

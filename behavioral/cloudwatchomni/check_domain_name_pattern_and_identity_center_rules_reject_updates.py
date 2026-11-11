"""domain-name-pattern-and-identity-center-rules-reject-updates."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-pattern-and-identity-center-rules-reject-updates"
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
    """UpdateDomain refuses an uppercase name and a switch to IDC with no Identity Center instance,
    each with its own message, and the domain keeps its name and providers.
    """
    cwo = ctx.client("cloudwatchomni")
    created = _domain(ctx, cwo)
    domain_id = created["domainId"]

    code, message = _error(lambda: cwo.update_domain(domainId=domain_id, name="Sim2Real-Behav-Upper"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: Member must satisfy "
        "regular expression pattern: [a-z0-9]+(-[a-z0-9]+)*"
    ), f"unexpected message {message!r}"
    code, message = _error(lambda: cwo.update_domain(domainId=domain_id, identityProviders=["IDC"]))
    assert (code, message) == (
        "ValidationException", "identityCenterInstanceArn is required when authorizationProviders includes IDC"
    ), f"unexpected answer to IDC without an instance: {code}: {message!r}"

    got = cwo.get_domain(domainId=domain_id)["domain"]
    assert got["name"] == created["name"], f"a refused update renamed the domain to {got.get('name')!r}"
    assert got["identityProviders"] == ["IAM"], f"a refused update changed providers to {got['identityProviders']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

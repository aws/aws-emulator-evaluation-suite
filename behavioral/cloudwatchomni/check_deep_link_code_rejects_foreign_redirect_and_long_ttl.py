"""deep-link-code-rejects-foreign-redirect-and-long-ttl."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-link-code-rejects-foreign-redirect-and-long-ttl"
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
    """CreateOneTimeDeepLinkCode refuses a redirect URL outside the domain and a TTL above 600
    seconds, each with its own message, and answers not found for an unknown domain.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]

    code, message = _error(lambda: cwo.create_one_time_deep_link_code(
        domainId=domain_id, redirectUrl="https://example.com/auth/callback"))
    assert (code, message) == ("ValidationException", "Invalid redirect URI: unrecognized domain"), (
        f"unexpected answer to a foreign redirect: {code}: {message!r}"
    )
    code, message = _error(lambda: cwo.create_one_time_deep_link_code(domainId=domain_id, ttlSeconds=601))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "1 validation error detected: Value at 'ttlSeconds' failed to satisfy constraint: Member must have "
        "value less than or equal to 600"
    ), f"unexpected message {message!r}"
    code, message = _error(lambda: cwo.create_one_time_deep_link_code(domainId="d-sim2realbehavmissing00"))
    assert (code, message) == ("ResourceNotFoundException", "Domain not found"), (
        f"unexpected answer for an unknown domain: {code}: {message!r}"
    )
    ok = cwo.create_one_time_deep_link_code(domainId=domain_id, ttlSeconds=600)
    assert ok["code"], "a TTL of exactly 600 seconds must be accepted"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

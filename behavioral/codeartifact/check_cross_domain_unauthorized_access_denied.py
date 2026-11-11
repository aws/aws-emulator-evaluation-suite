"""cross-domain-unauthorized-access-denied."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "cross-domain-unauthorized-access-denied"
GROUP = "overly-permissive"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role with no codeartifact grant and no domain-policy statement is refused GetRepositoryEndpoint
    with AccessDeniedException naming the role, the action and the repository, while the owner's call
    returns an https endpoint: CodeArtifact denies by default."""
    ca = ctx.client("codeartifact")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(
        domain=domain, repository=repository, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    # A domain policy exists, but its only statement covers a DIFFERENT action
    # (DescribeDomain) for the account root -- it has no statement matching the
    # unprivileged role or the GetRepositoryEndpoint action.
    domain_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RootCanDescribeOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "codeartifact:DescribeDomain",
                    "Resource": "*",
                }
            ],
        }
    )
    ca.put_domain_permissions_policy(domain=domain, policyDocument=domain_policy)

    role_name = ctx.unique_name("sim2real-ca-noperm-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # Deliberately attach NO permissions policy: this principal can assume the role
    # but has no grant for any codeartifact action.

    session_name = ctx.unique_name("sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    unprivileged_ca = _client_as(ctx, "codeartifact", creds)

    refusal = _error(
        lambda: unprivileged_ca.get_repository_endpoint(
            domain=domain, repository=repository, format="generic"
        )
    )
    expected = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: codeartifact:GetRepositoryEndpoint on resource: "
        f"arn:aws:codeartifact:{ctx.region}:{account_id}:repository/{domain}/{repository} because "
        f"no identity-based policy allows the codeartifact:GetRepositoryEndpoint action",
    )
    assert refusal == expected, (
        f"a principal with no identity grant and no domain-policy statement must be denied "
        f"GetRepositoryEndpoint with {expected!r}; got {refusal!r}"
    )

    # Positive control: the domain owner's own credentials, which are exempt from
    # the (irrelevant, same-account) domain resource policy, succeed normally.
    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository, format="generic")
    assert endpoint["repositoryEndpoint"].startswith("https://"), (
        f"the domain owner's own call must still succeed with a real endpoint URL; "
        f"got {endpoint['repositoryEndpoint']!r}"
    )


def _client_as(ctx, service: str, creds: dict[str, str]):
    """A client signing as the minted (unprivileged) principal, built through ctx.client so it
    reaches whichever target the run is pointed at."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _assume_role_with_retry(
    sts, role_arn: str, session_name: str, timeout_s: float = 30.0, interval_s: float = 2.0
) -> dict[str, str]:
    """IAM role assumability lags role creation by a few seconds; poll until it works."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except Exception as exc:  # eventual-consistency propagation delay
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc}")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of a call that MUST be rejected; raises if it succeeds."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

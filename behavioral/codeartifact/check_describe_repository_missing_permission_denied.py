"""describe-repository-missing-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "describe-repository-missing-permission-denied"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeRepository by a role with no IAM permissions is AccessDeniedException, and granting
    that one permission makes the identical call succeed through the same assumed-role session."""
    ca = ctx.client("codeartifact")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()
    repo = ctx.unique_name("sim2real-ca-repo-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    # Positive control: the caller's own (permitted) credentials can describe the repository.
    described = ca.describe_repository(domain=domain, repository=repo)["repository"]
    assert described["name"] == repo, f"expected {repo!r}, got {described.get('name')!r}"

    role_name = ctx.unique_name("sim2real-ca-noperm-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # Deliberately attach NO permissions policy to the role -- this is the ONE thing broken.

    session_name = ctx.unique_name("sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    unprivileged_ca = ctx.client(
        "codeartifact",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # A freshly minted session can be refused as an unrecognized token for a few seconds; wait
    # that out (bounded) so the graded refusal is the authorization decision.
    deadline = time.monotonic() + 60.0
    while True:
        refusal = _error(lambda: unprivileged_ca.describe_repository(domain=domain, repository=repo))
        if refusal[0] != "UnrecognizedClientException" or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    repo_arn = f"arn:aws:codeartifact:{ctx.region}:{account_id}:repository/{domain}/{repo}"
    expected = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: codeartifact:DescribeRepository on resource: {repo_arn} because "
        f"no identity-based policy allows the codeartifact:DescribeRepository action",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Restore: grant the SAME role the SAME permission it was denied, and demand the IDENTICAL
    # call now succeeds through the SAME assumed-role session.
    grant_policy_name = "allow-describe-repository"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=grant_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "codeartifact:DescribeRepository",
                    "Resource": repo_arn,
                }],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=grant_policy_name))

    restored = _poll_until_success(
        lambda: unprivileged_ca.describe_repository(domain=domain, repository=repo)["repository"],
        timeout_s=60.0,
        interval_s=3.0,
        description="the grant becomes effective for the same assumed-role session",
    )
    assert restored["name"] == repo, f"expected {repo!r}, got {restored.get('name')!r}"


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
    """The captured AWS (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _poll_until_success(
    fn: Callable[[], Any], *, timeout_s: float, interval_s: float, description: str
) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

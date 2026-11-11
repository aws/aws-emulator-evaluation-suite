"""domain-permissions-policy-server-enforced-on-repository-actions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-permissions-policy-server-enforced-on-repository-actions"
GROUP = "server-side"
SERVICES = ["codeartifact"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A domain policy allowing only one named role ListRepositoriesInDomain is enforced: that role,
    with no identity-based CodeArtifact permission, succeeds via the resource grant, while a
    sibling role named in neither an identity policy nor the domain policy is denied.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-cadompol-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.describe_domain(domain=domain)["domain"]["arn"]

    repo = ctx.unique_name("repo-")
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    granted_role_arn = _create_bare_role(ctx, ctx.unique_name("ca-dgranted-"))
    other_role_name = ctx.unique_name("ca-dother-")
    other_role_arn = _create_bare_role(ctx, other_role_name)

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GrantListRepositoriesInDomain",
                "Effect": "Allow",
                "Principal": {"AWS": granted_role_arn},
                "Action": ["codeartifact:ListRepositoriesInDomain"],
                "Resource": "*",
            }
        ],
    }
    _put_policy_with_retry(
        lambda: ca.put_domain_permissions_policy(
            domain=domain, policyDocument=json.dumps(policy_doc)
        )
    )

    granted_creds = _assume_role_creds(ctx, granted_role_arn, "dgranted")

    other_creds = _assume_role_creds(ctx, other_role_arn, "dother")

    granted_ca = _client_as(ctx, "codeartifact", granted_creds)
    other_ca = _client_as(ctx, "codeartifact", other_creds)

    resp = _poll_until_success(lambda: granted_ca.list_repositories_in_domain(domain=domain))
    names = [r["name"] for r in resp["repositories"]]
    assert repo in names, (
        f"{granted_role_arn} was named alone in the domain permissions policy for "
        f"ListRepositoriesInDomain, has no identity-based CodeArtifact permission, yet did not see "
        f"{repo!r} in {names!r} -- the resource-based grant did not take effect"
    )

    account = _account_id(ctx)
    refusal = _error(lambda: other_ca.list_repositories_in_domain(domain=domain))
    expected = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account}:assumed-role/{other_role_name}/dother is not authorized to "
        f"perform: codeartifact:ListRepositoriesInDomain on resource: "
        f"arn:aws:codeartifact:{ctx.region}:{account}:domain/{domain} because no identity-based "
        f"policy allows the codeartifact:ListRepositoriesInDomain action",
    )
    assert refusal == expected, (
        f"{other_role_arn} is named in neither an identity policy nor the domain permissions "
        f"policy, so ListRepositoriesInDomain must be denied with {expected!r}; got {refusal!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_bare_role(ctx, name: str) -> str:
    iam = ctx.client("iam")
    acct = _account_id(ctx)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return resp["Role"]["Arn"]


def _assume_role_creds(ctx, role_arn: str, session_name: str, timeout_s: float = 60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn}: {last_exc}")


def _client_as(ctx, service: str, creds):
    """A client signing as the assumed role, built through ctx.client so it reaches whichever
    target the run is pointed at."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _poll_until_success(fn, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded (IAM propagation?): {last_exc}")


def _put_policy_with_retry(fn, timeout_s: float = 45.0, interval_s: float = 3.0):
    """Retry a PutXPermissionsPolicy call: a just-created role ARN may not yet resolve as a
    Principal (IAM propagation), which surfaces as ValidationException; retry for a bounded window.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"policy was never accepted (IAM propagation?): {last_exc}")


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected AccessDeniedException but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

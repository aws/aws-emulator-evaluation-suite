"""authorization-token-needs-sts-bearer-permission-that-a-domain-policy-cannot-grant."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorization-token-needs-sts-bearer-permission-that-a-domain-policy-cannot-grant"
GROUP = "authorization-tokens"
SERVICES = ["codeartifact"]

#: How long a freshly created role may take to become assumable.
_ASSUME_WAIT_SECONDS = 180.0

#: How long the domain resource policy may take to start granting DescribeDomain. A resource policy
#: that has not taken effect within this window is itself the finding, not a reason to wait longer.
_POLICY_EFFECT_WAIT_SECONDS = 180.0

#: How long the identity-policy grant may take to make GetAuthorizationToken succeed.
#: IAM identity-policy changes are eventually consistent.
_POLICY_GRANT_WAIT_SECONDS = 180.0


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAuthorizationToken needs sts:GetServiceBearerToken in the caller's IDENTITY policy; granting
    it in the domain resource policy has no effect, even once that same document's DescribeDomain
    grant is demonstrably live. Granting it in the identity policy makes the identical call succeed.

    Reference: https://docs.aws.amazon.com/codeartifact/latest/ug/tokens-authentication.html
    """
    ca = ctx.client("codeartifact")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    domain = ctx.unique_name("sim2real-ca-dom-")
    repository = ctx.unique_name("sim2real-ca-repo-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, repository))

    role_name = ctx.unique_name("sim2real-ca-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                       "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-ca-inline"
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, policy_name))

    # ---- beat 1: the identity policy grants everything except sts:GetServiceBearerToken -------
    # The role holds the bearer grant only from the last beat on, so no propagation of a removed
    # grant can let a refused call through.
    _put_policy(iam, role_name, policy_name, _statements(with_bearer=False))
    session = _assume(ctx, role_arn)
    restricted_ca = ctx.client("codeartifact", creds=session)
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/sim2real-ca"
    expected_denial = (
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: sts:GetServiceBearerToken on "
        f"resource: {session_arn} because no identity-based policy allows the "
        f"sts:GetServiceBearerToken action",
    )
    # Until the new inline policy propagates, the refusal names codeartifact:GetAuthorizationToken.
    denied = _poll(
        lambda: _token_or_code(restricted_ca, domain),
        lambda r: not isinstance(r, tuple) or "sts:GetServiceBearerToken" in r[1],
        timeout_s=min(_ASSUME_WAIT_SECONDS, ctx.time_left() or _ASSUME_WAIT_SECONDS), interval_s=2.0,
        reason="the role's inline policy granting codeartifact:GetAuthorizationToken to take effect")
    assert denied == expected_denial, (
        f"without sts:GetServiceBearerToken GetAuthorizationToken returned {denied!r}; "
        f"expected {expected_denial!r}: codeartifact:GetAuthorizationToken is granted, and the "
        f"message names sts:GetServiceBearerToken, so this refusal is distinguishable from a "
        f"missing codeartifact:GetAuthorizationToken"
    )

    # ---- beat 2: the effect is absent, and the credential is otherwise healthy --------------
    # DescribeRepository is granted in the identity policy, so a working answer here proves
    # the denial is scoped to the token operation rather than a dead session.
    healthy = restricted_ca.describe_repository(domain=domain, repository=repository)
    assert healthy["repository"]["name"] == repository, (
        f"the restricted session read back repository {healthy['repository']!r}, expected "
        f"{repository!r} — if this failed too, the AccessDeniedException above would prove nothing"
    )

    # ---- beat 3: the DOMAIN RESOURCE POLICY grant does not substitute -----------------------
    # One document, two grants. codeartifact:DescribeDomain is the twin control: the restricted
    # role's identity policy does NOT grant it, so the moment it starts working is the moment this
    # document is live — and sts:GetServiceBearerToken must still be inert at that same moment.
    resource_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": ["codeartifact:DescribeDomain", "codeartifact:GetAuthorizationToken",
                       "sts:GetServiceBearerToken"],
            "Resource": "*",
        }],
    }
    ca.put_domain_permissions_policy(domain=domain, policyDocument=json.dumps(resource_policy))
    ctx.on_cleanup(lambda: _delete_domain_policy(ca, domain))

    live = _poll(
        lambda: _describe_domain_or_code(restricted_ca, domain),
        lambda r: isinstance(r, dict),
        timeout_s=min(_POLICY_EFFECT_WAIT_SECONDS, ctx.time_left() or _POLICY_EFFECT_WAIT_SECONDS), interval_s=2.0,
        reason="the domain resource policy's codeartifact:DescribeDomain grant to take effect, "
               "which is the twin control proving the whole document is live")
    assert live["domain"]["name"] == domain, (
        f"the domain resource policy's DescribeDomain grant returned {live!r}, expected domain "
        f"{domain!r}"
    )
    still_denied = _token_or_code(restricted_ca, domain)
    assert still_denied == expected_denial, (
        f"with sts:GetServiceBearerToken granted in the DOMAIN RESOURCE POLICY (and the same "
        f"document's DescribeDomain grant demonstrably live in this same instant), "
        f"GetAuthorizationToken returned {still_denied!r}; the documented contract is that the "
        f"permission has no effect in that policy, so it must still be {expected_denial!r}"
    )
    # Freeze detector: for 30 s after the policy went live the grant must not quietly take effect.
    live_at = time.monotonic()
    while time.monotonic() - live_at < 30.0:
        time.sleep(2.0)
        repeat = _token_or_code(restricted_ca, domain)
        assert repeat == expected_denial, (
            f"{time.monotonic() - live_at:.0f}s after the resource policy went live, got "
            f"{repeat!r}; a domain-policy grant of sts:GetServiceBearerToken must never begin "
            f"to work"
        )

    # ---- beat 4: grant the identity permission; the IDENTICAL call then succeeds ------------
    _put_policy(iam, role_name, policy_name, _statements(with_bearer=True))
    granted = _poll(
        lambda: _token_or_code(restricted_ca, domain),
        lambda r: isinstance(r, dict),
        timeout_s=min(_POLICY_GRANT_WAIT_SECONDS, ctx.time_left() or _POLICY_GRANT_WAIT_SECONDS), interval_s=2.0,
        reason="granting sts:GetServiceBearerToken in the IDENTITY policy to make the identical "
               "GetAuthorizationToken call succeed")
    assert granted["authorizationToken"], (
        f"after granting the identity permission the identical call returned "
        f"{ {k: ('<token>' if k == 'authorizationToken' else v) for k, v in granted.items()} !r}; "
        f"expected a non-empty token"
    )
    # Terminal read at the destination, through a different operation than the one that minted:
    # the granted session reads this domain's repository endpoint.
    endpoint = restricted_ca.get_repository_endpoint(
        domain=domain, repository=repository, format="npm")["repositoryEndpoint"]
    assert endpoint.startswith("https://") and domain in endpoint and repository in endpoint, (
        f"GetRepositoryEndpoint returned {endpoint!r} for domain {domain!r} repository "
        f"{repository!r}; the granted session must be able to address its own repository"
    )


def _statements(*, with_bearer: bool) -> list[dict]:
    """The restricted role's identity policy. Exactly one statement differs between the two arms."""
    statements = [
        # A harmless grant: an inline policy cannot be empty.
        {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
        {"Effect": "Allow",
         "Action": ["codeartifact:GetAuthorizationToken", "codeartifact:DescribeRepository",
                    "codeartifact:GetRepositoryEndpoint"],
         "Resource": "*"},
    ]
    if with_bearer:
        statements.append(
            {"Effect": "Allow", "Action": "sts:GetServiceBearerToken", "Resource": "*"})
    return statements


def _put_policy(iam, role_name: str, policy_name: str, statements: list[dict]) -> None:
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))


def _assume(ctx, role_arn: str) -> dict[str, str]:
    """Assume *role_arn*, retrying while the brand-new role is not yet assumable. RAISES on
    timeout: an unassumable role is a hard failure, never a reason to fall back to the caller's own
    credentials, which would send the asserted calls as an admin."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + _ASSUME_WAIT_SECONDS
    last = None
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-ca",
                                    DurationSeconds=3600)["Credentials"]
            return {"aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"]}
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"role {role_arn!r} was not assumable within {_ASSUME_WAIT_SECONDS}s; last "
                    f"error {last!r}"
                ) from exc
            time.sleep(5.0)


def _token_or_code(client, domain: str):
    """GetAuthorizationToken's response dict, or the (code, message) it was refused with."""
    try:
        return client.get_authorization_token(domain=domain, durationSeconds=900)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")


def _describe_domain_or_code(client, domain: str):
    """DescribeDomain's response dict, or the AWS error code it was refused with."""
    try:
        return client.describe_domain(domain=domain)
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _poll(read, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry on an observable condition. RAISES on timeout, naming what it waited for."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = read()
        if predicate(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason}; last observation was {observed!r}"
            )
        time.sleep(interval_s)


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_domain_policy(ca, domain: str) -> None:
    try:
        ca.delete_domain_permissions_policy(domain=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_repository(ca, domain: str, repository: str, timeout_s: float = 120.0) -> None:
    """DeleteRepository, retrying while the service still sees a dependent reference."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repository)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_domain(ca, domain: str, timeout_s: float = 120.0) -> None:
    """DeleteDomain, retrying while the service still sees a repository in the domain."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

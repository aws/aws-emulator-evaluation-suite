"""iam-policy-without-create-repository-blocks-only-that-action."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-policy-without-create-repository-blocks-only-that-action"
GROUP = "overly-permissive"
SERVICES = ["ecr-public", "iam"]

_KEY_ACTIVATION_BUDGET_S = 120.0
_KEY_ACTIVATION_INTERVAL_S = 3.0
# A write-action grant (CreateRepository) can take minutes to take effect, far longer than a read
# grant; this is a ceiling, not a fixed wait.
_POLICY_BUDGET_S = 300.0
_POLICY_INTERVAL_S = 3.0

_READ_ONLY_ACTIONS = ["ecr-public:DescribeRepositories", "ecr-public:GetAuthorizationToken"]
_WRITE_ACTION = "ecr-public:CreateRepository"
# ecr-public:GetAuthorizationToken also requires sts:GetServiceBearerToken in the caller's identity
# policy; it is granted in both arms so the CreateRepository denial is never entangled with it.
_STS_BEARER_ACTION = "sts:GetServiceBearerToken"


def _public_ecr_host(host: str) -> bool:
    """``public.ecr.<domain>``: the ECR Public service labels lead, then the target's own domain."""
    labels = host.split(".")
    return labels[:2] == ["public", "ecr"] and len(labels) > 2 and all(labels[2:])


# The scoped client is built with ctx.client(..., creds=) so the second identity reaches the same
# endpoint as the first.


def _error_message_and_code(fn, *, what: str) -> tuple[str, str]:
    """Call fn and return (code, message) from the ClientError. RAISES on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"{what} succeeded; it must have been refused")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that raises on exhaustion rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} was not observed within {timeout_s}s; last read was {last!r}"
    )


def _ecr_public(ctx, creds=None):
    """ECR Public's control plane is served only from us-east-1; `creds=` re-signs for the scoped
    principal without changing the endpoint."""
    if creds is None:
        return ctx.client("ecr-public", region="us-east-1")
    return ctx.client("ecr-public", region="us-east-1", creds=creds)


def _inline_policy(actions) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": "*"}],
        },
        separators=(",", ":"),
    )


def _scoped_principal(ctx):
    """Create an IAM user with a read-only ecr-public inline policy and an access key, and return
    (user_name, user_arn, policy_name, creds). Every created object registers its own teardown, in
    an order IAM accepts: the key and the inline policy go before the user."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-ecrpub-iam-")
    user_arn = iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = ctx.unique_name("sim2real-behav-ecrpub-pol-")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=_inline_policy([*_READ_ONLY_ACTIONS, _STS_BEARER_ACTION]),
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )
    creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    return user_name, user_arn, policy_name, creds


def _describe_named(ecr, repository_name):
    """DescribeRepositories for one name: the repository dict, or None if the service says it is
    not there. Callers assert on the result explicitly."""
    try:
        return ecr.describe_repositories(repositoryNames=[repository_name])["repositories"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "RepositoryNotFoundException":
            return None
        raise


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IAM policy that omits ecr-public:CreateRepository blocks a REAL signed CreateRepository
    from that principal while the same principal's DescribeRepositories still succeeds."""
    iam = ctx.client("iam")
    admin_ecr = _ecr_public(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    user_name, user_arn, policy_name, creds = _scoped_principal(ctx)
    scoped_ecr = _ecr_public(ctx, creds=creds)
    scoped_sts = ctx.client("sts", creds=creds)

    # --- the credential is live at all. sts:GetCallerIdentity needs no IAM permission, so this
    # separates "the key is not active yet" from "the policy denies" -- without it, a
    # not-yet-propagated key reads as a successful authorization refusal.
    identity = _poll_until(
        lambda: _caller_arn(scoped_sts),
        lambda arn: arn == user_arn,
        timeout_s=_KEY_ACTIVATION_BUDGET_S,
        interval_s=_KEY_ACTIVATION_INTERVAL_S,
        description=f"the new access key resolving to {user_arn} via sts:GetCallerIdentity",
    )
    assert identity == user_arn, (
        f"the scoped credential signs as {identity!r}, expected the created user {user_arn!r}"
    )

    # --- BEAT 1: POSITIVE CONTROL, on the SAME PRINCIPAL. -----------------------------------------
    # Without it, "CreateRepository is denied" is indistinguishable from "this principal is denied everything ecr-public".
    listed = _poll_until(
        lambda: _describe_ok(scoped_ecr),
        lambda ok: ok is True,
        timeout_s=_POLICY_BUDGET_S,
        interval_s=_POLICY_INTERVAL_S,
        description=(
            f"the read-only inline policy on {user_name} permitting "
            f"ecr-public:DescribeRepositories"
        ),
    )
    assert listed is True, (
        f"the scoped principal cannot call DescribeRepositories despite an explicit Allow; the "
        f"denial below would prove nothing (last probe {listed!r})"
    )
    # ...and the second Allowed action works too, so the Allow is real and not a fluke of one op.
    token = scoped_ecr.get_authorization_token()["authorizationData"]
    assert token.get("authorizationToken"), (
        f"the scoped principal's GetAuthorizationToken returned no token: {token!r}"
    )

    # --- BEAT 2: break exactly one thing -- the policy omits CreateRepository ---------------------
    repo_name = ctx.unique_name("sim2real-behav-ecrpub-iamrepo-")
    # Registered BEFORE the create is attempted, so a target that wrongly ALLOWS the create still
    # gets the repository torn down rather than leaking a world-visible public repository.
    ctx.on_cleanup(
        lambda: admin_ecr.delete_repository(repositoryName=repo_name, force=True)
    )

    def _scoped_create():
        return scoped_ecr.create_repository(repositoryName=repo_name)

    code, message = _error_message_and_code(
        _scoped_create,
        what=(
            f"CreateRepository as {user_name}, whose inline policy Allows only "
            f"{_READ_ONLY_ACTIONS}"
        ),
    )
    assert code == "AccessDeniedException", (
        f"CreateRepository from a principal without {_WRITE_ACTION} was refused {code!r}, "
        f"expected AccessDeniedException"
    )
    assert message == f"User: {identity} is not authorized to perform: ecr-public:CreateRepository on resource: arn:aws:ecr-public::{ctx.account}:repository/{repo_name} because no identity-based policy allows the ecr-public:CreateRepository action", (
        f"expected the exact AccessDeniedException message AWS returns, got {message!r}"
    )
    assert _WRITE_ACTION in message, (
        f"the denial message does not name the action that was denied, so it cannot be told apart "
        f"from a blanket denial: {message!r} (expected it to mention {_WRITE_ACTION!r})"
    )

    # --- BEAT 3: the effect is ABSENT, read at the destination by a DIFFERENT principal -----------
    absent_code, _ = _error_message_and_code(
        lambda: admin_ecr.describe_repositories(repositoryNames=[repo_name]),
        what=f"DescribeRepositories for the denied repository {repo_name} as the harness principal",
    )
    assert absent_code == "RepositoryNotFoundException", (
        f"the harness principal's DescribeRepositories for the denied repository answered "
        f"{absent_code!r}, expected RepositoryNotFoundException"
    )

    # --- BEAT 4: RESTORE -- add the one missing action, change nothing else -----------------------
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=_inline_policy([*_READ_ONLY_ACTIONS, _STS_BEARER_ACTION, _WRITE_ACTION]),
    )

    # --- BEAT 5: the IDENTICAL call now succeeds --------------------------------------------------
    created = _poll_until(
        lambda: _create_or_code(_scoped_create),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=_POLICY_BUDGET_S,
        interval_s=_POLICY_INTERVAL_S,
        description=(
            f"the identical CreateRepository succeeding as {user_name} after {_WRITE_ACTION} was "
            f"added to its inline policy"
        ),
    )
    assert created["repository"]["repositoryName"] == repo_name, (
        f"the restored create made {created['repository'].get('repositoryName')!r}, "
        f"expected {repo_name!r}"
    )

    # --- BEAT 6: the terminal read is at the DESTINATION, through a different operation and a
    # different principal than the one that mutated. -----------------------------------------------
    repo = _poll_until(
        lambda: _describe_named(admin_ecr, repo_name),
        lambda r: r is not None,
        timeout_s=_POLICY_BUDGET_S,
        interval_s=_POLICY_INTERVAL_S,
        description=(
            f"the harness principal's DescribeRepositories reporting {repo_name} after the scoped "
            f"principal created it"
        ),
    )
    assert repo is not None, f"DescribeRepositories never reported {repo_name}"
    assert repo["repositoryName"] == repo_name, (
        f"DescribeRepositories reported repositoryName {repo['repositoryName']!r}, "
        f"expected {repo_name!r}"
    )
    assert repo["registryId"] == account_id, (
        f"the repository created by the scoped principal is registered under "
        f"{repo['registryId']!r}, expected the caller's account {account_id!r}"
    )
    # repositoryUri is public.ecr.<domain>/<alias>/<name>; the domain is the target's own.
    host, _, path = repo["repositoryUri"].partition("/")
    assert _public_ecr_host(host) and path.count("/") >= 1, (
        f"the repository's URI is {repo['repositoryUri']!r}; an ECR Public repository is "
        f"public.ecr.<domain>/<alias>/<name>"
    )
    assert repo["repositoryUri"].endswith(f"/{repo_name}"), (
        f"the repository's URI {repo['repositoryUri']!r} does not end in the repository name "
        f"{repo_name!r}"
    )


def _caller_arn(sts):
    """sts:GetCallerIdentity's Arn, or the error code if the credential is not live yet. The
    caller's poll asserts equality with the expected ARN and RAISES on exhaustion, so a
    never-activating key fails."""
    try:
        return sts.get_caller_identity()["Arn"]
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _describe_ok(ecr) -> object:
    """True if DescribeRepositories is permitted, else the error code. The caller's poll RAISES on
    exhaustion, so a permanently denied read fails rather than passing silently."""
    try:
        ecr.describe_repositories(maxResults=1)
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return True


def _create_or_code(fn) -> object:
    """The CreateRepository response dict on success, else the error code. The caller's poll
    RAISES on exhaustion, so a permanently denied create fails."""
    try:
        return fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

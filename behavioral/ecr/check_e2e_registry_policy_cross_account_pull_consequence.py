"""e2e-registry-policy-cross-account-pull-consequence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-registry-policy-cross-account-pull-consequence"
GROUP = "server-side"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """A registry policy granting a permissionless role ecr:CreateRepository lets that role create
    a repository with its own credentials, and deleting the policy denies it again."""
    ecr = ctx.client("ecr")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    # Registry policies accept only registry-scoped actions (pulls are governed by repository
    # policies), so CreateRepository is the grant under test. A same-account role with no
    # identity policy exercises the same resource-policy evaluation a cross-account caller uses.
    role_name = ctx.unique_name("sim2real-ecr-second-principal-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]
    role_arn = role["Arn"]
    role_id = role["RoleId"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name))

    session_creds = _poll_until(
        lambda: _try_assume_role(sts, role_arn),
        lambda creds: creds is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assumed_ecr = ctx.client(
        "ecr",
        creds={
            "aws_access_key_id": session_creds["AccessKeyId"],
            "aws_secret_access_key": session_creds["SecretAccessKey"],
            "aws_session_token": session_creds["SessionToken"],
        },
    )
    # GetAuthorizationToken needs an identity permission and cannot be granted by a registry
    # policy, so it runs with the primary caller's credentials.
    auth = ecr.get_authorization_token()
    assert auth["authorizationData"][0][
        "authorizationToken"
    ], f"expected a non-empty authorizationToken, got {auth['authorizationData'][0]!r}"

    pre_grant_repo_name = ctx.unique_name("sim2real-ecr-regpol-pre-")
    denied_before_code, denied_before_message = _poll_until_denied(
        ctx, assumed_ecr, pre_grant_repo_name, timeout_s=30.0, interval_s=2.0
    )
    assert denied_before_code == "AccessDeniedException", (
        f"expected AccessDeniedException creating a repository with no registry policy "
        f"grant in place, got {denied_before_code!r}"
    )
    expected = _denied_message(account_id, role_name, ctx.region, pre_grant_repo_name)
    assert denied_before_message == expected, (
        f"expected the pre-grant denial {expected!r}, got {denied_before_message!r}"
    )

    registry_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSecondPrincipalCreateRepository",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": ["ecr:CreateRepository"],
                "Resource": [f"arn:aws:ecr:{ctx.region}:{account_id}:repository/*"],
            }
        ],
    }
    original_registry_policy = _get_registry_policy_text_or_none(ecr)
    ctx.on_cleanup(lambda: _restore_registry_policy(ctx, original_registry_policy))
    ecr.put_registry_policy(policyText=json.dumps(registry_policy))
    stored_policy = ecr.get_registry_policy()
    # The stored policy may carry the role's unique principal id instead of the ARN sent.
    stored_text = stored_policy["policyText"]
    assert role_arn in stored_text or role_id in stored_text, (
        f"expected the created role ({role_arn}, unique id {role_id}) as the Principal in "
        f"the stored registry policy, got {stored_text!r}"
    )

    granted_repo_name = ctx.unique_name("sim2real-ecr-regpol-granted-")
    created = _poll_until(
        lambda: _try_create_repository(assumed_ecr, granted_repo_name),
        lambda result: result is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    ctx.on_cleanup(lambda: _safe_delete_repository(ctx, granted_repo_name))
    assert (
        created["repositoryName"] == granted_repo_name
    ), f"expected create_repository's own response to name {granted_repo_name!r}, got {created!r}"

    # Read back with the primary credentials, not just the CreateRepository echo.
    described = ecr.describe_repositories(repositoryNames=[granted_repo_name])["repositories"]
    assert described and described[0]["repositoryName"] == granted_repo_name, (
        f"expected an independent describe_repositories read to show {granted_repo_name!r}, "
        f"got {described!r}"
    )

    ecr.delete_registry_policy()

    # The policy delete can lag the API response, so retry until the call is denied.
    denied_code, denied_message, denied_repo_name = _poll_until_denied_after_policy_delete(ctx, assumed_ecr)
    assert denied_code == "AccessDeniedException", (
        f"expected AccessDeniedException creating a repository after the registry policy "
        f"grant was deleted, got {denied_code!r}"
    )
    expected = _denied_message(account_id, role_name, ctx.region, denied_repo_name)
    assert denied_message == expected, (
        f"expected the post-delete denial {expected!r}, got {denied_message!r}"
    )


def _denied_message(account_id: str, role_name: str, region: str, repo_name: str) -> str:
    """The AccessDeniedException message CreateRepository returns to the assumed role."""
    return (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-ecr-pull is not "
        f"authorized to perform: ecr:CreateRepository on resource: "
        f"arn:aws:ecr:{region}:{account_id}:repository/{repo_name} because no identity-based "
        f"policy allows the ecr:CreateRepository action"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last}")


def _poll_until_denied_after_policy_delete(ctx, assumed_ecr, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Retry CreateRepository with a fresh name until denied, deleting any repository created
    while the DeleteRegistryPolicy is still propagating."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        attempt_repo_name = ctx.unique_name("sim2real-ecr-regpol-post-")
        try:
            assumed_ecr.create_repository(repositoryName=attempt_repo_name)
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "AccessDeniedException":
                return last_code, err.response["Error"].get("Message", ""), attempt_repo_name
        else:
            _safe_delete_repository(ctx, attempt_repo_name)
            last_code = None
        time.sleep(interval_s)
    raise AssertionError(f"registry policy delete never took effect, last_code={last_code}")


def _try_assume_role(sts, role_arn: str):
    try:
        return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-ecr-pull")[
            "Credentials"
        ]
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _try_create_repository(client, repo_name: str):
    try:
        return client.create_repository(repositoryName=repo_name)["repository"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDeniedException":
            return None
        raise


def _poll_until_denied(ctx, assumed_ecr, repo_name: str, *, timeout_s: float, interval_s: float):
    """The denial's (code, message) once CreateRepository as the assumed role is denied; a success
    raises. UnrecognizedClientException is retried: fresh session credentials take seconds to
    propagate."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            result = assumed_ecr.create_repository(repositoryName=repo_name)
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "AccessDeniedException":
                return last_code, err.response["Error"].get("Message", "")
            if last_code != "UnrecognizedClientException":
                raise
        else:
            ctx.on_cleanup(lambda: _safe_delete_repository(ctx, repo_name))
            raise AssertionError(
                f"expected a ClientError, but the call succeeded and returned {result!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"never observed AccessDeniedException within {timeout_s}s, last_code={last_code}"
    )


def _safe_delete_repository(ctx, repo_name: str) -> None:
    ecr = ctx.client("ecr")
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _safe_delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _get_registry_policy_text_or_none(ecr):
    try:
        return ecr.get_registry_policy()["policyText"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None
        raise


def _restore_registry_policy(ctx, original_policy_text) -> None:
    ecr = ctx.client("ecr")
    if original_policy_text is None:
        try:
            ecr.delete_registry_policy()
        except ClientError as err:
            if err.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                raise
    else:
        ecr.put_registry_policy(policyText=original_policy_text)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""put-resource-permission-statement-concurrent-same-token-idempotent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-permission-statement-concurrent-same-token-idempotent"
GROUP = "concurrency"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal with an explicit Allow on signin:PutResourcePermissionStatement, proven live via
    ListResourcePermissionStatements, is still refused Put with AccessDeniedException "No Access to
    PutResourcePermissionStatement API", and no statement is created.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-signin-rp-")
    policy_name = ctx.unique_name("sim2real-signin-rp-policy-")
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "signin:PutResourcePermissionStatement",
                        "signin:ListResourcePermissionStatements",
                    ],
                    "Resource": "*",
                }
            ],
        }
    )

    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]}
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    signin = ctx.client("signin", creds=creds)

    # Positive control: the same freshly granted principal reaches the read side of this API once
    # its credentials have propagated, so the refusal below is a capability gate, not a token that
    # is not live yet. ResourceNotFoundException counts as reachable; only propagation errors retry.
    def _list_reachable():
        try:
            signin.list_resource_permission_statements(maxResults=1)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    _retry_until_usable(_list_reachable)

    excluded = _caller_role_arn(ctx)
    token = ctx.unique_name("sim2real-token-")
    code, message = _retry_while_propagating(
        lambda: _error(
            lambda: signin.put_resource_permission_statement(excludedPrincipal=excluded, clientToken=token)
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}: {message}"
    assert message == "No Access to PutResourcePermissionStatement API", (
        f"expected the exact denial 'No Access to PutResourcePermissionStatement API', got: {message!r}"
    )

    # Effect absent: the denied call must not have created a statement anyway.
    def _list_statements():
        return signin.list_resource_permission_statements(maxResults=100).get("permissionStatements", [])

    try:
        stmts = _retry_until_usable(_list_statements)
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException or an empty list, got {err.response['Error']['Code']!r}"
        )
        assert err.response["Error"].get("Message") == "Requested resource not found", (
            f"expected message 'Requested resource not found', got {err.response['Error'].get('Message')!r}"
        )
    else:
        assert stmts == [], f"expected no permission statements after a denied Put, found {stmts!r}"


def _caller_role_arn(ctx) -> str:
    ident = ctx.client("sts").get_caller_identity()
    arn, account = ident["Arn"], ident["Account"]
    if ":assumed-role/" in arn:
        role_name = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _retry_until_usable(fn, *, timeout_s: float = 60):
    """A freshly created IAM access key + inline policy is eventually consistent for
    signing/authorization; bound the wait rather than assume it is instant or retry
    forever."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "UnrecognizedClientException"):
                raise
            last_err = err
            time.sleep(2)
    raise AssertionError(
        f"freshly-created IAM access key never became usable within {timeout_s}s: {last_err}"
    )


def _retry_while_propagating(fn, *, timeout_s: float = 60):
    """Re-run fn() while the new key still reads as not-yet-live: each signin endpoint
    sees the fresh access key on its own schedule, so one usable call does not settle the next."""
    deadline = time.monotonic() + timeout_s
    code, message = fn()
    while code in ("InvalidClientTokenId", "UnrecognizedClientException") and time.monotonic() < deadline:
        time.sleep(2)
        code, message = fn()
    return code, message


def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

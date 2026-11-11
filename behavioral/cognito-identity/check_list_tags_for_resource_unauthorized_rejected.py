"""list-tags-for-resource-unauthorized-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-tags-for-resource-unauthorized-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource from a zero-permission IAM user is refused with AccessDeniedException,
    and granting exactly that action on exactly that pool makes the identical call succeed.
    """
    ci = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx)
    arn = _pool_arn(ctx, pool_id)
    ci.tag_resource(ResourceArn=arn, Tags={"Environment": "test"})

    # A same-account proxy: a pool owned by another account would need a second AWS account.
    unauthorized_ci, unauthorized_user, user_arn = _no_permission_client(ctx, "cognito-identity")
    code, message = _error(lambda: unauthorized_ci.list_tags_for_resource(ResourceArn=arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected = (
        f"User: {user_arn} is not authorized to perform: cognito-identity:ListTagsForResource "
        f"on resource: {arn} because no identity-based policy allows the "
        "cognito-identity:ListTagsForResource action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # sanity: the same call succeeds for the pool's actual owner, proving the resource is real
    # and the rejection above is specifically about the unauthorized caller.
    tags_seen = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_seen.get("Environment") == "test", (
        f"expected tag Environment=test as the owner, got {tags_seen!r}"
    )

    # restore: grant the identical denied principal permission for exactly this action and
    # resource, then demand the identical call now succeeds.
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-allow-")
    iam.put_user_policy(
        UserName=unauthorized_user,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "cognito-identity:ListTagsForResource",
                "Resource": arn,
            }],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=unauthorized_user, PolicyName=policy_name)
    )

    restored_tags = _poll_until(
        lambda: unauthorized_ci.list_tags_for_resource(ResourceArn=arn)["Tags"],
        timeout_s=30.0,
        description="the identical caller to be allowed after gaining the exact permission",
    )
    assert restored_tags.get("Environment") == "test", (
        f"expected the now-permitted identical caller to see tag Environment=test, "
        f"got {restored_tags!r}"
    )


def _create_pool(ctx, **extra) -> str:
    ci = ctx.client("cognito-identity")
    name = extra.pop("IdentityPoolName", None) or ctx.unique_name("sim2real-behav-")
    allow_unauth = extra.pop("AllowUnauthenticatedIdentities", True)
    resp = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **extra
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


def _no_permission_client(ctx, service_name: str):
    """Create a brand-new IAM user with no attached policies and return a client for
    ``service_name`` authenticated as that user (implicit-deny on every action), with the
    user's name and ARN."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-noperm-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(
            UserName=user_name, AccessKeyId=access_key["AccessKeyId"]
        )
    )

    creds = {
        "aws_access_key_id": access_key["AccessKeyId"],
        "aws_secret_access_key": access_key["SecretAccessKey"],
    }

    # New IAM credentials are eventually consistent; poll (bounded) until they authenticate.
    # GetCallerIdentity requires no IAM permission, so this isolates "key active" from
    # "action authorized".
    probe = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + 30.0
    authenticated = False
    while time.monotonic() < deadline:
        try:
            probe.get_caller_identity()
            authenticated = True
            break
        except ClientError:
            time.sleep(1.5)
    if not authenticated:
        raise AssertionError("new IAM access key never became usable for authentication")

    return ctx.client(service_name, creds=creds), user_name, user_arn


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(fn, *, timeout_s, interval_s=1.5, description="condition"):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{description} not reached within {timeout_s}s; last error {last_exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

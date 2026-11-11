"""delete-identity-pool-not-authorized-cross-account."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identity-pool-not-authorized-cross-account"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIdentityPool by a permission-less IAM user is refused with AccessDeniedException and
    the pool survives; the owner's own delete then succeeds and the pool stays not-found.
    """
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_id = _create_pool(ctx, ci)

    # A same-account permission-less user: a true cross-account caller needs a second account.
    user_name = ctx.unique_name("sim2real-behav-noperm-")
    try:
        iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    except ClientError as exc:
        raise AssertionError(f"cannot create IAM user for negative test: {exc}") from exc
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    try:
        key = iam.create_access_key(UserName=user_name)["AccessKey"]
    except ClientError as exc:
        raise AssertionError(f"cannot create IAM access key for negative test: {exc}") from exc
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    restricted_creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }
    restricted_sts = ctx.client("sts", creds=restricted_creds)
    restricted_identity = _poll_until(
        lambda: _try_get_caller_identity(restricted_sts),
        lambda result: result is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    if restricted_identity is None:
        raise AssertionError("new IAM access key never became usable within 30s")

    own_identity = sts.get_caller_identity()
    assert restricted_identity["Arn"] != own_identity["Arn"], (
        f"the restricted probe must resolve to a distinct principal from the real caller, "
        f"got {restricted_identity['Arn']!r} for both"
    )

    restricted_ci = ctx.client("cognito-identity", creds=restricted_creds)
    denied = _error(lambda: restricted_ci.delete_identity_pool(IdentityPoolId=pool_id))
    account = own_identity["Account"]
    expected_denied = (
        "AccessDeniedException",
        f"User: {restricted_identity['Arn']} is not authorized to perform:"
        f" cognito-identity:DeleteIdentityPool on resource:"
        f" arn:aws:cognito-identity:{ctx.region}:{account}:identitypool/{pool_id}"
        f" because no identity-based policy allows the cognito-identity:DeleteIdentityPool action",
    )
    assert denied == expected_denied, (
        f"a caller with no cognito-identity permissions must be refused with "
        f"{expected_denied!r}, got {denied!r}"
    )

    # The forbidden effect did not happen: the pool still exists under the real caller.
    survived = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert survived["IdentityPoolId"] == pool_id, (
        f"the pool must survive the denied delete; describe returned {survived!r}"
    )

    # Restore: the SAME call, from the account's own authorized caller, must succeed -- the
    # boundary just crossed was the restricted caller's permissions, not the operation or the
    # pool. This doubles as the check's teardown for pool_id (asserted, not silent).
    ci.delete_identity_pool(IdentityPoolId=pool_id)
    not_found = ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found.")
    gone = _error(lambda: ci.describe_identity_pool(IdentityPoolId=pool_id))
    assert gone == not_found, (
        f"the pool's real owner must be able to delete it once the negative is proven; "
        f"describe after the authorized delete returned {gone!r} instead of not-found"
    )
    redelete = _error(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    assert redelete == not_found, (
        f"a mutation on the already-deleted pool id must keep failing not-found rather than "
        f"silently succeeding; got {redelete!r}"
    )


def _create_pool(ctx, ci, *, unauth: bool = True) -> str:
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=unauth,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(ci, pool_id))
    return pool_id


def _delete_pool_if_present(ci, pool_id):
    """Teardown-only: the body already deletes pool_id as an assertion, so tolerate it being
    gone by the time cleanup runs."""
    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _try_get_caller_identity(sts_client):
    try:
        return sts_client.get_caller_identity()
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    return result if predicate(result) else None


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

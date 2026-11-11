"""create-identity-source-nonexistent-user-pool-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-identity-source-nonexistent-user-pool-rejected"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIdentitySource with a malformed user pool ARN and with a well-formed ARN of a missing
    user pool each fail with ValidationException and the exact message and leave no identity
    source, while a real user pool yields the only listed identity source."""
    client = ctx.client("verifiedpermissions")
    idp = ctx.client("cognito-idp")
    account = ctx.client("sts").get_caller_identity()["Account"]
    store_id = _create_policy_store(ctx, client)

    # Positive control: CreateIdentitySource succeeds for a real, existing pool.
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-vp-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    real_arn = f"arn:aws:cognito-idp:{ctx.region}:{account}:userpool/{pool_id}"

    created = client.create_identity_source(
        policyStoreId=store_id,
        configuration={"cognitoUserPoolConfiguration": {"userPoolArn": real_arn}},
    )
    source_id = created["identitySourceId"]
    assert source_id, f"expected an identitySourceId for a real user pool, got {created!r}"

    sources = _retry_until_ready(
        lambda: client.list_identity_sources(policyStoreId=store_id)
    )["identitySources"]
    assert [s["identitySourceId"] for s in sources] == [source_id], (
        f"expected only the positive-control source {source_id!r} listed, got {sources!r}"
    )

    # Negative 1: an ARN whose shape doesn't match a Cognito user pool ARN at all
    # (wrong service segment) is rejected before any existence lookup.
    malformed_arn = f"arn:aws:s3:::not-a-user-pool-{ctx.region}"
    malformed = _error(
        lambda: client.create_identity_source(
            policyStoreId=store_id,
            configuration={"cognitoUserPoolConfiguration": {"userPoolArn": malformed_arn}},
        )
    )
    expected_malformed = (
        "ValidationException",
        "1 validation error detected. Value at '/configuration/cognitoUserPoolConfiguration/"
        "userPoolArn' failed to satisfy constraint: Member must satisfy regular expression pattern: "
        r"^arn:[a-zA-Z0-9-]+:cognito-idp:(([a-zA-Z0-9-]+:\d{12}:userpool/[\w-]+_[0-9a-zA-Z]+))$",
    )
    assert malformed == expected_malformed, (
        f"expected {expected_malformed!r} for a malformed userPoolArn, got {malformed!r}"
    )

    # Negative 2: a syntactically well-formed ARN naming a user pool that does
    # not exist is rejected too -- the ARN's shape being valid is not enough.
    nonexistent_arn = f"arn:aws:cognito-idp:{ctx.region}:{account}:userpool/{ctx.region}_ffffffff9"
    nonexistent = _error(
        lambda: client.create_identity_source(
            policyStoreId=store_id,
            configuration={"cognitoUserPoolConfiguration": {"userPoolArn": nonexistent_arn}},
        )
    )
    expected_nonexistent = (
        "ValidationException",
        f"User pool {ctx.region}_ffffffff9 does not exist.",
    )
    assert nonexistent == expected_nonexistent, (
        f"expected {expected_nonexistent!r} for a nonexistent user pool ARN, got {nonexistent!r}"
    )

    # effect absent: neither rejected call created an identity source; only the
    # positive control's source exists in the store.
    sources_after = _retry_until_ready(
        lambda: client.list_identity_sources(policyStoreId=store_id)
    )["identitySources"]
    assert [s["identitySourceId"] for s in sources_after] == [source_id], (
        f"expected only the positive-control source to remain, got {sources_after!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _retry_until_ready(fn, timeout: float = 30.0, interval: float = 1.5):
    """A freshly created policy store can lag briefly before control-plane
    reads (like ListIdentitySources) see it; retry on ResourceNotFoundException
    up to timeout seconds before giving up."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

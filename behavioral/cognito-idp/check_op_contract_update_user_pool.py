"""op-contract-update-user-pool."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-update-user-pool"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPool: success path persists new pool config; unknown pool -> ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-pool-")
    created = idp.create_user_pool(
        PoolName=pool_name,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        AutoVerifiedAttributes=[],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    pool = created["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    # --- success-path contract: multiple distinct fields updated in one call ---
    update_resp = idp.update_user_pool(
        UserPoolId=pool_id,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 12,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        AdminCreateUserConfig={"AllowAdminCreateUserOnly": True},
        DeletionProtection="INACTIVE",
    )
    assert update_resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    # UpdateUserPool returns an (essentially) empty body -- the contract is that the
    # mutation is durable and observable via DescribeUserPool, not the response shape.
    assert "UserPool" not in update_resp

    described = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert described["Policies"]["PasswordPolicy"]["MinimumLength"] == 12, (
        f"expected updated MinimumLength=12, got {described['Policies']['PasswordPolicy']}"
    )
    assert described["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True
    assert described["DeletionProtection"] == "INACTIVE"
    # Immutable/unrelated fields must survive the partial update untouched.
    assert described["Name"] == pool_name
    assert described["Id"] == pool_id
    # LastModifiedDate must have advanced as an observable side-effect of the update.
    assert described["LastModifiedDate"] > pool["CreationDate"], (
        f"expected LastModifiedDate to advance past creation ({pool['CreationDate']}), "
        f"got {described['LastModifiedDate']}"
    )

    # --- distinct error boundary: unknown (but well-formed) UserPoolId ---
    bogus_pool_id = f"{ctx.region}_ZZZZZZZZZ"
    code, message = _error(
        lambda: idp.update_user_pool(
            UserPoolId=bogus_pool_id,
            Policies={"PasswordPolicy": {"MinimumLength": 10}},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # AWS sends this refusal with an empty message body.
    assert message == "", f"expected an empty message, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

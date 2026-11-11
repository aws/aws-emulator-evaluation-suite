"""invalid-pool-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-pool-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: an invalid PoolName MUST be rejected."""
    c = ctx.client("cognito-idp")

    # Positive control: CreateUserPool must work at all for this account/credentials,
    # so the rejection below is attributable to the bad name, not to a dead endpoint.
    good_name = ctx.unique_name("sim2real-behav-cip-pool-")
    pool_id = c.create_user_pool(
        PoolName=good_name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    bad_name = "bad/pool*name!"
    code, message = _error(lambda: c.create_user_pool(PoolName=bad_name))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an invalid PoolName, got {code}"
    )
    expected = (
        "1 validation error detected: Value 'bad/pool*name!' at 'poolName' failed to satisfy"
        r" constraint: Member must satisfy regular expression pattern: [\w\s+=,.@-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at the destination: the rejected name must never have landed.
    token = None
    for _ in range(200):  # bounded pagination walk across the account's pools
        kwargs = {"MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        resp = c.list_user_pools(**kwargs)
        names = {p["Name"] for p in resp["UserPools"]}
        assert bad_name not in names, (
            f"expected no pool named {bad_name!r} after rejected CreateUserPool, "
            "found it via ListUserPools"
        )
        token = resp.get("NextToken")
        if not token:
            break


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

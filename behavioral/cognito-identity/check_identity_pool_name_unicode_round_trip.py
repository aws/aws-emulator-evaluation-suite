"""identity-pool-name-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-pool-name-unicode-round-trip"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IdentityPoolName using every symbol and space of the class `[\\w\\s+=,.@-]+` is returned
    byte-identical by CreateIdentityPool and DescribeIdentityPool; a name with a non-ASCII letter is
    refused with ValidationException and the exact message and creates no pool."""
    cognito = ctx.client("cognito-identity")

    # Exercise every character class the pattern allows: word chars, space,
    # and the literal symbols + = , . @ -
    allowed_suffix = " a_B9+=,.@-end"
    pool_name = ctx.unique_name("sim2real-idp-") + allowed_suffix
    assert len(pool_name) <= 128, f"test fixture name exceeds the 128-char API limit: {len(pool_name)}"

    created = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))

    # The create response itself should already echo the name unchanged.
    assert created["IdentityPoolName"] == pool_name, (
        f"CreateIdentityPool did not echo the name byte-identically: "
        f"expected {pool_name!r}, got {created['IdentityPoolName']!r}"
    )

    described = cognito.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolName"] == pool_name, (
        f"DescribeIdentityPool did not preserve the name byte-identically: "
        f"expected {pool_name!r}, got {described['IdentityPoolName']!r}"
    )
    # No trimming/collapsing drift: exact codepoint sequence, including the
    # interior/edge whitespace and symbol runs.
    assert list(described["IdentityPoolName"]) == list(pool_name), (
        f"codepoint sequence drifted: expected {list(pool_name)!r}, "
        f"got {list(described['IdentityPoolName'])!r}"
    )

    # A name with a character outside that class (an accented Latin letter) is rejected; the
    # round-trip create above is the positive control for CreateIdentityPool.
    unicode_name = ctx.unique_name("sim2real-idp-") + " Café"
    code, message = _error(
        lambda: cognito.create_identity_pool(
            IdentityPoolName=unicode_name,
            AllowUnauthenticatedIdentities=True,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a non-ASCII IdentityPoolName, got {code!r}"
    )
    expected = (
        f"1 validation error detected: Value '{unicode_name}' at 'identityPoolName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [\\w\\s+=,.@-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no pool with the rejected name shows up in ListIdentityPools.
    found = False
    next_token = None
    while True:
        kwargs = {"MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cognito.list_identity_pools(**kwargs)
        for pool in page.get("IdentityPools", []):
            if pool.get("IdentityPoolName") == unicode_name:
                found = True
        next_token = page.get("NextToken")
        if not next_token or found:
            break
    assert not found, f"rejected pool {unicode_name!r} nonetheless appeared in ListIdentityPools"


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


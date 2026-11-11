"""identity-pool-name-invalid-symbol-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-pool-name-invalid-symbol-rejected"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IdentityPoolName of symbols outside `^[\\w\\s+=,.@-]+$` (emoji, currency signs) is
    rejected with ValidationException and creates no pool; an allowed-character name succeeds."""
    cognito = ctx.client("cognito-identity")

    invalid_name = ctx.unique_name("sim2real-idp-") + " \u2603\u2665\U0001F600\u00a3\u20ac"

    def _create_invalid():
        resp = cognito.create_identity_pool(
            IdentityPoolName=invalid_name,
            AllowUnauthenticatedIdentities=True,
        )
        # If a target wrongly accepts the name, do not leak the pool.
        leaked_id = resp.get("IdentityPoolId")
        if leaked_id:
            ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=leaked_id))
        return resp

    code, status, message = _error(_create_invalid)
    # The pattern is enforced by generic shape validation (ValidationException), not the
    # domain-specific InvalidParameterException.
    assert code == "ValidationException", (
        f"expected ValidationException for a name built from disallowed symbols, got {code!r}"
    )
    assert status == 400, f"expected HTTP 400 for the rejected name, got {status!r}"
    expected_message = f"1 validation error detected: Value '{invalid_name}' at 'identityPoolName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w\\s+=,.@-]+"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert invalid_name in message, f"expected the message to echo the rejected name, got {message!r}"

    found = False
    next_token = None
    while True:
        kwargs = {"MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cognito.list_identity_pools(**kwargs)
        for pool in resp.get("IdentityPools", []):
            if pool.get("IdentityPoolName") == invalid_name:
                found = True
        next_token = resp.get("NextToken")
        if not next_token or found:
            break
    assert not found, f"rejected pool name {invalid_name!r} appeared in ListIdentityPools anyway"

    valid_name = ctx.unique_name("sim2real-idp-") + " valid+=,.@-name"
    created = cognito.create_identity_pool(
        IdentityPoolName=valid_name,
        AllowUnauthenticatedIdentities=True,
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))
    assert created["IdentityPoolName"] == valid_name, (
        f"expected create response to echo {valid_name!r}, got {created.get('IdentityPoolName')!r}"
    )

    described = cognito.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolName"] == valid_name, (
        f"expected describe_identity_pool to show {valid_name!r} for {pool_id}, "
        f"got {described.get('IdentityPoolName')!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.response["Error"]["Code"], status, err.response["Error"].get("Message") or ""
    raise AssertionError(
        f"expected create_identity_pool to reject the invalid name, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

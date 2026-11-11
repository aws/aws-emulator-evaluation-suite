"""get-open-id-token-invalid-identity-id-rejected."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-open-id-token-invalid-identity-id-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpenIdToken with a syntactically invalid IdentityId (no region:guid separator)
    is rejected with ValidationException, not a token -- distinct from a real, well-formed
    IdentityId issued by GetId, which the positive control shows actually mints one."""
    ci = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]

    # Positive control: a real, well-formed IdentityId issues a real OpenId token.
    control = ci.get_open_id_token(IdentityId=identity_id)
    assert control["IdentityId"] == identity_id, (
        f"expected control IdentityId {identity_id!r}, got {control['IdentityId']!r}"
    )
    assert control["Token"], f"expected a non-empty Token, got {control['Token']!r}"

    # Break exactly one thing: the IdentityId's syntax (no ':' region/guid separator at all).
    # IdentityId must match pattern [\w-]+:[0-9a-f-]+ (REGION:GUID) -- this has no ':' separator.
    bad_identity_id = "not-a-valid-identity-id"
    code, message = _refusal(lambda: ci.get_open_id_token(IdentityId=bad_identity_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == (
        f"1 validation error detected: Value '{bad_identity_id}' at 'identityId' failed to "
        r"satisfy constraint: Member must satisfy regular expression pattern: [\w-]+:[0-9a-f-]+"
    ), message


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

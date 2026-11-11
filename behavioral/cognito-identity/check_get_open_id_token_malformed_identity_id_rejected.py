"""get-open-id-token-malformed-identity-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-malformed-identity-id-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpenIdToken with a syntactically malformed IdentityId (missing the
    region:guid separator) is rejected as ValidationException -- distinct from a
    well-formed IdentityId that simply doesn't exist, which is ResourceNotFoundException."""
    cip = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = cip.get_id(IdentityPoolId=pool_id)["IdentityId"]

    # Positive control: a real, well-formed IdentityId issues a real OpenId token.
    control = cip.get_open_id_token(IdentityId=identity_id)
    assert control["IdentityId"] == identity_id, (
        f"expected control IdentityId {identity_id!r}, got {control['IdentityId']!r}"
    )
    assert control["Token"], "expected a non-empty Token from the positive control"

    # Break exactly one thing: the IdentityId's syntax (no region:guid separator at all).
    malformed_id = "malformed-identity-id-without-colon-or-guid"
    code, message = _error(lambda: cip.get_open_id_token(IdentityId=malformed_id))
    assert code == "ValidationException", (
        f"expected ValidationException for a syntactically malformed IdentityId, got {code!r}"
    )
    expected = (
        f"1 validation error detected: Value '{malformed_id}' at 'identityId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w-]+:[0-9a-f-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Distinct case: a well-formed but nonexistent identity id -> a different error class.
    nonexistent_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    code2, message2 = _error(lambda: cip.get_open_id_token(IdentityId=nonexistent_id))
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent IdentityId, got {code2!r}"
    )
    expected2 = f"Identity '{nonexistent_id}' not found."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

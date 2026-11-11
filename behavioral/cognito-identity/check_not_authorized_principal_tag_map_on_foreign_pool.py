"""not-authorized-principal-tag-map-on-foreign-pool."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "not-authorized-principal-tag-map-on-foreign-pool"
GROUP = 'error-semantics'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS rejects must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Principal-tag attribute-map operations (Get/SetPrincipalTagAttributeMap) against a nonexistent
    identity pool raise ResourceNotFoundException, consistent with the rest of the pool-scoped API."""
    ev = ctx.client("cognito-identity")
    foreign_pool_id = f"{ctx.region}:{uuid.uuid4()}"
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{ctx.region}_doesnotexist"

    # Positive control: the identical Set/Get pair against a pool that DOES exist. Without this, a
    # target that rejects every Get/SetPrincipalTagAttributeMap call (regardless of pool) would pass
    # this check for the wrong reason. SetPrincipalTagAttributeMap requires the provider to be one
    # actually associated with the pool (real AWS: InvalidParameterException, "Provider ... not
    # configured for Identity Pool" -- true even for a non-Cognito provider name), so the pool is
    # created with a SupportedLoginProviders entry for the control provider.
    control_provider_name = "graph.facebook.com"
    real_pool_id = ev.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={control_provider_name: "1234567890123456"},
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=real_pool_id))

    ev.set_principal_tag_attribute_map(
        IdentityPoolId=real_pool_id, IdentityProviderName=control_provider_name, PrincipalTags={"department": "sub"}
    )
    got = ev.get_principal_tag_attribute_map(
        IdentityPoolId=real_pool_id, IdentityProviderName=control_provider_name
    )
    assert got["PrincipalTags"] == {"department": "sub"}, (
        f"positive control: expected the just-set PrincipalTags to read back, got {got}"
    )

    expected_message = f"IdentityPool '{foreign_pool_id}' not found."

    code, message = _error(
        lambda: ev.get_principal_tag_attribute_map(
            IdentityPoolId=foreign_pool_id, IdentityProviderName=provider_name
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for GetPrincipalTagAttributeMap on a nonexistent pool, got {code}"
    )
    assert message == expected_message, (
        f"GetPrincipalTagAttributeMap: expected message {expected_message!r}, got {message!r}"
    )

    code, message = _error(
        lambda: ev.set_principal_tag_attribute_map(
            IdentityPoolId=foreign_pool_id, IdentityProviderName=provider_name, UseDefaults=True
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for SetPrincipalTagAttributeMap on a nonexistent pool, got {code}"
    )
    assert message == expected_message, (
        f"SetPrincipalTagAttributeMap: expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""disassociate-identity-provider-config-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")

CHECK = "disassociate-identity-provider-config-not-found"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateIdentityProviderConfig with an unsupported type fails with InvalidParameterException,
    while the same call with type oidc on the same made-up cluster fails with ResourceNotFoundException.
    """
    c = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-behav-no-cluster-")
    config_name = ctx.unique_name("sim2real-behav-idp-")

    code, _ = _expect_error(
        lambda: c.disassociate_identity_provider_config(
            clusterName=cluster_name,
            identityProviderConfig={
                "type": "not-a-supported-type",
                "name": config_name,
            },
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"

    # Positive control: the same clusterName/name with the one valid type ("oidc")
    # takes a genuinely different code path -- cluster resolution, not type
    # validation -- which confirms the InvalidParameterException above is specific
    # to the unsupported type value rather than every call on this identity being
    # uniformly rejected.
    code2, _ = _expect_error(
        lambda: c.disassociate_identity_provider_config(
            clusterName=cluster_name,
            identityProviderConfig={"type": "oidc", "name": config_name},
        )
    )
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for valid type/unknown cluster, got {code2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

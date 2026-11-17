"""eks-associate-identity-provider-config-unknown-cluster-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-associate-identity-provider-config-unknown-cluster-rejected"
GROUP = "validation"
SERVICES = ["eks"]


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateIdentityProviderConfig and DescribeIdentityProviderConfig against a cluster name
    that does not exist are both refused with the cluster's own not-found error.
    """
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-idp-missing-")

    code, message = _error(
        lambda: eks.associate_identity_provider_config(
            clusterName=name,
            oidc={
                "identityProviderConfigName": ctx.unique_name("sim2real-eks-idp-cfg-"),
                "issuerUrl": "https://example.com",
                "clientId": "sim2real-eks-idp-test-client",
            },
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"No cluster found for name: {name}."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    code2, message2 = _error(
        lambda: eks.describe_identity_provider_config(
            clusterName=name, identityProviderConfig={"type": "oidc", "name": "sim2real-eks-idp-absent"}
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2!r}"
    assert message2 == "The requested resource does not exist.", f"unexpected message: {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

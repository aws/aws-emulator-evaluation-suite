"""describe-identity-provider-config-unknown-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-identity-provider-config-unknown-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityProviderConfig against a cluster that does not exist raises
    ResourceNotFoundException with AWS's generic "The requested resource does not exist." message --
    the distinct not-found path from an unknown config name on a real cluster."""
    eks = ctx.client("eks")
    fake_cluster = ctx.unique_name("sim2real-eks-nonexistent-")
    fake_config_name = ctx.unique_name("sim2real-oidc-")

    code, msg = _error_code_and_message(
        lambda: eks.describe_identity_provider_config(
            clusterName=fake_cluster,
            identityProviderConfig={"type": "oidc", "name": fake_config_name},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} ({msg!r})"
    expected = "The requested resource does not exist."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _error_code_and_message(fn):
    """Call fn(); return (Code, Message) of the error it raises. An unexpected success
    raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return e["Code"], e.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

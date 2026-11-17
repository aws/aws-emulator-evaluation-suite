"""create-capability-invalid-delete-propagation-policy-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-capability-invalid-delete-propagation-policy-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]

_BAD_POLICY = ("InvalidParameterException", "Invalid delete propagation policy")


def expect_error(fn: Callable[[], Any], code: str, message: str) -> None:
    """Call fn, require it raises a ClientError whose (Code, Message) is exactly this pair."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapability with a deletePropagationPolicy outside RETAIN is rejected with
    InvalidParameterException before the named cluster is even looked up.
    """
    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-nocluster-")
    role_arn = f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-eks-caprole-')}"
    capability_name = ctx.unique_name("sim2real-cap-")

    expect_error(
        lambda: eks.create_capability(
            clusterName=cluster_name,
            capabilityName=capability_name,
            type="KRO",
            roleArn=role_arn,
            deletePropagationPolicy="DELETE_EVERYTHING",
        ),
        *_BAD_POLICY,
    )

    # Positive control: the one modelled value ("RETAIN") passes this validation and
    # the call fails for a later, different reason -- the cluster does not exist --
    # which shows the rejection above is specific to deletePropagationPolicy, not a
    # catch-all for any malformed CreateCapability request.
    expect_error(
        lambda: eks.create_capability(
            clusterName=cluster_name,
            capabilityName=capability_name,
            type="KRO",
            roleArn=role_arn,
            deletePropagationPolicy="RETAIN",
        ),
        "ResourceNotFoundException",
        f"No cluster found for name: {cluster_name}.",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

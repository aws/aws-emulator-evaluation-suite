"""create-access-entry-malformed-principal-arn-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-access-entry-malformed-principal-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]

_BAD_PRINCIPAL = ("InvalidParameterException", "The principalArn parameter format is not valid")


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
    """CreateAccessEntry with a principalArn that is not ARN-shaped is rejected with
    InvalidParameterException before the named cluster is even looked up.
    """
    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-eks-nocluster-")

    expect_error(
        lambda: eks.create_access_entry(clusterName=cluster_name, principalArn="not-an-arn"),
        *_BAD_PRINCIPAL,
    )

    # Positive control: an ARN-shaped principal passes format validation and the call
    # fails for a later, different reason -- the cluster does not exist -- which shows
    # the rejection above is specific to principalArn's syntax, not every call on this
    # made-up cluster.
    role_arn = f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-eks-norole-')}"
    expect_error(
        lambda: eks.create_access_entry(clusterName=cluster_name, principalArn=role_arn),
        "ResourceNotFoundException",
        f"No cluster found for name: {cluster_name}.",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""describe-agreement-malformed-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-agreement-malformed-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAgreement refuses an agreementId outside its character pattern with ValidationException,
    while a well-formed nonexistent id gets ResourceNotFoundException, each with its exact message.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")

    malformed = _error_code(lambda: mpa.describe_agreement(agreementId="not a valid id!!"))
    want = ("ValidationException", "Provided agreement id is invalid.")
    assert malformed == want, f"expected {want!r}, got {malformed!r}"

    # Positive control: a well-formed but nonexistent id is a *different*, more specific error.
    wellformed = _error_code(
        lambda: mpa.describe_agreement(agreementId=ctx.unique_name("sim2real-no-such-agreement-"))
    )
    want = ("ResourceNotFoundException", "Provided agreement does not exist.")
    assert wellformed == want, f"expected {want!r}, got {wellformed!r}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

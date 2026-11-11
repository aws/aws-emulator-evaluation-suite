"""op-contract-describeFastLaunchImages."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeFastLaunchImages"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFastLaunchImages returns the well-formed collection shape and rejects a
    nonexistent AMI ID."""
    ec2 = ctx.client("ec2")

    # --- success path: we have not enabled Windows fast launch on any AMI we own, so the
    # self-owned query must succeed with an empty (but well-typed) result ---
    resp = ec2.describe_fast_launch_images(
        Filters=[{"Name": "owner-id", "Values": [_account_id(ctx)]}]
    )
    assert "FastLaunchImages" in resp
    assert isinstance(resp["FastLaunchImages"], list)
    assert resp["FastLaunchImages"] == []

    # --- error boundary: a well-formed but nonexistent AMI ID must be rejected -- (this API
    # does not validate unrecognized filter names -- it silently ignores them -- so probe with
    # a bogus AMI ID instead, which is a reliably-enforced check) ---
    bogus_image_id = "ami-0123456789abcdef0"

    def _call():
        ec2.describe_fast_launch_images(ImageIds=[bogus_image_id])

    code, code_msg = _error(_call)
    assert code == "InvalidRequest", f"expected InvalidRequest for a bogus AMI ID, got {code!r}"
    assert code_msg == f"Can't describe EC2 Fast Launch images. Image ID: {bogus_image_id} is not valid.", (
        f"expected the exact InvalidRequest message, got {code_msg!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

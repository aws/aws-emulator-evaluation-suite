"""op-contract-get-default-credit-specification."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-default-credit-specification"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDefaultCreditSpecification returns the account's configured CPU credit
    mode for every burstable instance family, stably across repeat reads, and
    rejects a non-burstable family with the specific documented error."""
    ec2 = ctx.client("ec2")

    for family in ("t2", "t3", "t3a", "t4g"):
        spec = ec2.get_default_credit_specification(InstanceFamily=family)[
            "InstanceFamilyCreditSpecification"
        ]
        assert spec["InstanceFamily"] == family, (
            f"expected InstanceFamily {family!r} echoed back, got {spec['InstanceFamily']!r}"
        )
        cpu_credits = spec["CpuCredits"]
        assert cpu_credits in ("standard", "unlimited"), (
            f"unexpected CpuCredits value for {family}: {cpu_credits!r}"
        )

        # A read must not advance state: an immediate repeat read of the same,
        # untouched family returns the identical value.
        repeat = ec2.get_default_credit_specification(InstanceFamily=family)[
            "InstanceFamilyCreditSpecification"
        ]["CpuCredits"]
        assert repeat == cpu_credits, (
            f"GetDefaultCreditSpecification({family}) returned {cpu_credits!r} then "
            f"{repeat!r} on two consecutive reads with no modification in between"
        )

    # Error boundary: a real, non-burstable instance family is not a valid target
    # for a default credit specification and must be rejected with the specific
    # documented error, not merely "some error".
    code, message = _error(
        lambda: ec2.get_default_credit_specification(InstanceFamily="m5")
    )
    assert code == "InvalidInstanceFamily", (
        f"expected InvalidInstanceFamily for a non-burstable instance family, got {code!r}"
    )
    expected = (
        "The m5 instance family does not support Unlimited. Only burstable performance "
        "instance families support Unlimited. Change the instance family and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

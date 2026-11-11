"""modify-default-credit-specification-invalid-cpu-credits-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-default-credit-specification-invalid-cpu-credits-rejected"
GROUP = "data-plane"
SERVICES = ["ec2"]

_FAMILY = "t2"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-default-credit-specification")
def run(ctx) -> None:
    """ModifyDefaultCreditSpecification rejects an invalid CpuCredits value and leaves the setting unchanged."""
    ec2 = ctx.client("ec2")

    original = ec2.get_default_credit_specification(InstanceFamily=_FAMILY)[
        "InstanceFamilyCreditSpecification"
    ]["CpuCredits"]

    ctx.on_cleanup(lambda: _modify_with_retry(ec2, _FAMILY, original))

    # Positive control: a documented-valid value is accepted and reflected.
    _modify_with_retry(ec2, _FAMILY, "standard")
    reflected = _poll_until(
        lambda: ec2.get_default_credit_specification(InstanceFamily=_FAMILY)[
            "InstanceFamilyCreditSpecification"
        ]["CpuCredits"],
        lambda v: v == "standard",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert reflected == "standard", f"expected standard, got {reflected!r}"

    # Negative: only 'standard' and 'unlimited' are documented-valid CpuCredits values.
    code, msg = _error(
        lambda: ec2.modify_default_credit_specification(
            InstanceFamily=_FAMILY, CpuCredits="bogus-credits-value"
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = (
        "The CpuCredits parameter requires a value of either Standard or Unlimited. "
        "Change the value and try again."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Effect absent: the rejected attempt must not have changed the stored default.
    after = ec2.get_default_credit_specification(InstanceFamily=_FAMILY)[
        "InstanceFamilyCreditSpecification"
    ]["CpuCredits"]
    assert after == "standard", f"rejected ModifyDefaultCreditSpecification call still changed the value: {after}"


def _modify_with_retry(ec2, family: str, cpu_credits: str, *, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.modify_default_credit_specification(InstanceFamily=family, CpuCredits=cpu_credits)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("CreditSpecificationUpdateInProgress", "UpdateLimitExceeded"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(10.0)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {value!r}")


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

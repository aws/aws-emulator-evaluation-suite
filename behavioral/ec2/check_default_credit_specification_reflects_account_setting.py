"""default-credit-specification-reflects-account-setting."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-credit-specification-reflects-account-setting"
GROUP = "data-plane"
SERVICES = ["ec2"]

_FAMILY = "t3"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-default-credit-specification")
def run(ctx) -> None:
    """GetDefaultCreditSpecification returns the value most recently set, not a stale prior value."""
    ec2 = ctx.client("ec2")

    original = ec2.get_default_credit_specification(InstanceFamily=_FAMILY)[
        "InstanceFamilyCreditSpecification"
    ]["CpuCredits"]
    new_value = "unlimited" if original != "unlimited" else "standard"

    def _restore():
        _modify_with_retry(ec2, _FAMILY, original)

    ctx.on_cleanup(_restore)

    modified = _modify_with_retry(ec2, _FAMILY, new_value)
    assert modified["CpuCredits"] == new_value, (
        f"ModifyDefaultCreditSpecification's own response echoed {modified['CpuCredits']!r}, "
        f"not the requested {new_value!r}"
    )

    reflected = _poll_until(
        lambda: ec2.get_default_credit_specification(InstanceFamily=_FAMILY)[
            "InstanceFamilyCreditSpecification"
        ]["CpuCredits"],
        lambda v: v == new_value,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert reflected == new_value, (
        f"GetDefaultCreditSpecification returned stale value {reflected!r} instead of the "
        f"just-applied {new_value!r}"
    )


# ===== helpers =====
def _modify_with_retry(ec2, family: str, cpu_credits: str, *, timeout_s: float = 300.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.modify_default_credit_specification(
                InstanceFamily=family, CpuCredits=cpu_credits
            )["InstanceFamilyCreditSpecification"]
        except ClientError as exc:
            # UpdateLimitExceeded: a family's default can change only once per rolling 5 minutes.
            if exc.response["Error"]["Code"] not in ("CreditSpecificationUpdateInProgress", "UpdateLimitExceeded"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

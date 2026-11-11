"""tax-inheritance-requires-management-account."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tax-inheritance-requires-management-account"
GROUP = "overly-permissive"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTaxInheritance from an account that is not an organization's management account is refused with
    ValidationException and its exact message and leaves GetTaxInheritance unchanged; from a management
    account the value round-trips."""
    ts = ctx.client("taxsettings")

    try:
        original = ts.get_tax_inheritance()["heritageStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            raise AssertionError(
                "account has no tax-inheritance / consolidated billing family "
                "context (not an Organizations member account); "
                "PutTaxInheritance/GetTaxInheritance require one"
            )
        raise

    target = "OptOut" if original == "OptIn" else "OptIn"
    try:
        ts.put_tax_inheritance(heritageStatus=target)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException for a non-management-account Put, got {code!r}"
        )
        expected = "Only AWS orgs management account is allowed to set tax inheritance."
        message = exc.response["Error"].get("Message")
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        # Positive control: the read path is unaffected by this write-side
        # precondition -- it still returns the (unchanged) status.
        unchanged = ts.get_tax_inheritance()["heritageStatus"]
        assert unchanged == original, (
            f"expected heritageStatus to remain {original!r} after the rejected "
            f"PutTaxInheritance, got {unchanged!r}"
        )
        return

    # The caller is the organization's management account: the write applied.
    # Round-trip it and restore the original value.
    ctx.on_cleanup(lambda: ts.put_tax_inheritance(heritageStatus=original))
    final = _poll_until(
        lambda: ts.get_tax_inheritance()["heritageStatus"],
        lambda v: v == target,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert final == target, (
        f"expected heritageStatus to become {target!r} after the round-trip "
        f"PutTaxInheritance, got {final!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"condition never satisfied, last value={value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


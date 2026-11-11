"""describe-savings-plans-too-many-arns-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "describe-savings-plans-too-many-arns-rejected"
GROUP = "overly-permissive"
SERVICES = ["savingsplans"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlans rejects a savingsPlanArns list beyond the documented max of 100 with
    ValidationException, while the same well-formed-but-nonexistent ARNs within the bound succeed
    with an empty result (the positive control, proving the rejection is about count, not shape)."""
    sp = ctx.client("savingsplans")

    many_arns = [
        f"arn:aws:savingsplans::{ctx.account}:savingsplan/{uuid.uuid4()}" for _ in range(101)
    ]
    error = _error(lambda: sp.describe_savings_plans(savingsPlanArns=many_arns))
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for a 101-entry savingsPlanArns list "
        f"(the modelled max is 100), got {error!r}"
    )
    assert error["Message"] == (
        f"1 validation error detected: Value '[{', '.join(many_arns)}]' at "
        "'originalRequest.savingsPlanArns' failed to satisfy constraint: "
        "Member must have length less than or equal to 100"
    ), f"unexpected describe_101 message: {error['Message']!r}"

    few_arns = many_arns[:2]
    resp = sp.describe_savings_plans(savingsPlanArns=few_arns)
    plans = resp["savingsPlans"]
    assert plans == [], (
        f"expected an empty savingsPlans list for {len(few_arns)} well-formed but "
        f"nonexistent ARNs (proving the earlier rejection is about count, not shape), "
        f"got {plans!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

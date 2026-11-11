"""get-ops-summary-invalid-aggregator-rejected."""
from __future__ import annotations

import re
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-ops-summary-invalid-aggregator-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpsSummary with a well-formed Aggregator returns Entities, while an AggregatorType outside range|count|sum
    fails with ValidationException and the exact two-clause message."""
    ssm = ctx.client("ssm")

    # Positive control: a well-formed aggregator succeeds (Entities may be empty).
    # "count" aggregation requires an AttributeName to count distinct values of.
    positive = ssm.get_ops_summary(
        Aggregators=[
            {"AggregatorType": "count", "TypeName": "AWS:OpsItem", "AttributeName": "Status"}
        ]
    )
    assert "Entities" in positive, f"well-formed aggregator call did not return Entities: {positive!r}"

    def _call():
        ssm.get_ops_summary(
            Aggregators=[
                {
                    "AggregatorType": "not-a-real-aggregator-type",
                    "TypeName": "AWS:OpsItem",
                    "AttributeName": "Status",
                }
            ]
        )

    err = _error(_call)
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    # AWS lists the two constraint violations in a nondeterministic order, so the clauses are
    # graded as a set after the fixed prefix.
    prefix = "2 validation errors detected: "
    clause = (
        "Value 'not-a-real-aggregator-type' at 'aggregators.1.member.aggregatorType' failed to "
        "satisfy constraint: Member must "
    )
    expected_clauses = {
        clause + "satisfy regular expression pattern: ^(range|count|sum)",
        clause + "have length less than or equal to 20",
    }
    message = err.get("Message") or ""
    assert message.startswith(prefix), f"expected message to open with {prefix!r}, got {message!r}"
    clauses = message[len(prefix):].split("; ")
    assert len(clauses) == 2 and set(clauses) == expected_clauses, (
        f"expected the two clauses {sorted(expected_clauses)!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message); raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

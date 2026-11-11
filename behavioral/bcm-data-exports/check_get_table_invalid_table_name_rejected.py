"""get-table-invalid-table-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-table-invalid-table-name-rejected"
GROUP = "error-semantics"
SERVICES = ["bcm-data-exports"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTable rejects an unknown TableName with ValidationException."""
    bdx = ctx.client("bcm-data-exports")

    # Positive control: a real table name succeeds — otherwise "rejects an unknown
    # TableName" is indistinguishable from "rejects every GetTable".
    resp = bdx.get_table(TableName="COST_AND_USAGE_REPORT")
    assert resp["TableName"] == "COST_AND_USAGE_REPORT", (
        f"expected TableName=COST_AND_USAGE_REPORT, got {resp.get('TableName')!r}"
    )

    code, message = _error_code(lambda: bdx.get_table(TableName="NOT_A_REAL_TABLE_XYZ"))
    assert code == "ValidationException", (
        f"expected ValidationException for an unknown TableName, got {code!r}"
    )
    expected_message = "Table NOT_A_REAL_TABLE_XYZ not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

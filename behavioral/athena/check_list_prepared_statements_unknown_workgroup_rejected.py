"""list-prepared-statements-unknown-workgroup-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-prepared-statements-unknown-workgroup-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPreparedStatements against a WorkGroup that was never created is rejected with
    InvalidRequestException rather than returning an empty list as if it existed."""
    athena = ctx.client("athena")
    missing_workgroup = ctx.unique_name("sim2real-athena-missing-wg-")

    code, message = _error(lambda: athena.list_prepared_statements(WorkGroup=missing_workgroup))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for unknown workgroup {missing_workgroup!r}, got {code}"
    )
    assert message == "WorkGroup is not found.", (
        f"unexpected ListPreparedStatements message: {message!r}"
    )

    # positive control: a real, empty workgroup legitimately returns an empty list
    real_workgroup = ctx.unique_name("sim2real-athena-real-wg-")
    athena.create_work_group(Name=real_workgroup)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=real_workgroup))

    response = athena.list_prepared_statements(WorkGroup=real_workgroup)
    assert response["PreparedStatements"] == [], (
        f"expected no prepared statements in fresh workgroup {real_workgroup!r}, "
        f"got {response['PreparedStatements']}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

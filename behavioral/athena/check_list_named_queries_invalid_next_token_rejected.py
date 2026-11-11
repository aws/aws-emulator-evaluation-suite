"""list-named-queries-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-named-queries-invalid-next-token-rejected"
GROUP = "ordering"
SERVICES = ["athena"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed NextToken is rejected and does not disturb a subsequent valid listing."""
    athena = ctx.client("athena")
    workgroup = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(Name=workgroup, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(
        lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
    )
    resp = athena.create_named_query(
        Name=ctx.unique_name("sim2real-nq-"),
        Database="default",
        QueryString="SELECT 1",
        WorkGroup=workgroup,
    )
    expected_id = resp["NamedQueryId"]

    bad_token = "not-a-real-pagination-token=="
    code, message = _error(
        lambda: athena.list_named_queries(WorkGroup=workgroup, NextToken=bad_token)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == f"The nextPageToken is malformed: {bad_token}", (
        f"unexpected ListNamedQueries message: {message!r}"
    )

    # positive control (also proves the rejected call left state untouched): a valid,
    # unpaginated listing still finds the named query we created above.
    listing = athena.list_named_queries(WorkGroup=workgroup)
    assert expected_id in listing.get("NamedQueryIds", []), (
        "named query created before the rejected call is missing from a valid listing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

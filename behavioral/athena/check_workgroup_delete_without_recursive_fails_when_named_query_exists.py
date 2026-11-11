"""workgroup-delete-without-recursive-fails-when-named-query-exists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "workgroup-delete-without-recursive-fails-when-named-query-exists"
GROUP = 'overly-permissive'
SERVICES = ['athena']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkGroup is blocked while it owns a NamedQuery unless recursive delete is set."""
    athena = ctx.client("athena")

    # Positive control: a non-recursive delete of an EMPTY workgroup succeeds. Without this,
    # the negative below cannot distinguish "blocked because it owns a named query" from
    # "DeleteWorkGroup always requires RecursiveDeleteOption".
    empty_name = ctx.unique_name("sim2real-behav-wg-empty-")
    athena.create_work_group(Name=empty_name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=empty_name, RecursiveDeleteOption=True))
    athena.delete_work_group(WorkGroup=empty_name)
    empty_code, empty_message = _error(lambda: athena.get_work_group(WorkGroup=empty_name))
    assert empty_code == "InvalidRequestException", (
        f"expected a non-recursive delete of an empty workgroup to succeed and read as gone, "
        f"got {empty_code}"
    )
    assert empty_message == "WorkGroup is not found.", empty_message

    name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    nq_id = athena.create_named_query(
        Name=ctx.unique_name("sim2real-behav-nq-"),
        Database="default",
        QueryString="SELECT 1",
        WorkGroup=name,
    )["NamedQueryId"]

    code, message = _error(lambda: athena.delete_work_group(WorkGroup=name))
    assert code == "InvalidRequestException", (
        f"expected delete of non-empty workgroup to be blocked, got {code}"
    )
    assert message == f"WorkGroup {name} is not empty", message

    # workgroup and its named query must still exist after the failed delete
    athena.get_work_group(WorkGroup=name)
    athena.get_named_query(NamedQueryId=nq_id)

    # recursive delete succeeds and removes the workgroup + its contents
    athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)

    code, message = _error(lambda: athena.get_work_group(WorkGroup=name))
    assert code == "InvalidRequestException", f"expected workgroup gone, got {code}"
    assert message == "WorkGroup is not found.", message


def _error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

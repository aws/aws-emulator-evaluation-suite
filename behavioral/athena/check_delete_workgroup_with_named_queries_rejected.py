"""delete-workgroup-with-named-queries-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-workgroup-with-named-queries-rejected"
GROUP = "e2e"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Non-recursive DeleteWorkGroup on a workgroup holding a named query fails InvalidRequestException
    and leaves both intact; an empty sibling deletes with the same call, and the original deletes
    with RecursiveDeleteOption=True."""
    athena = ctx.client("athena")

    # Positive control: an empty sibling workgroup deletes fine WITHOUT the
    # recursive option, on the same call shape used below.
    empty_wg = ctx.unique_name("sim2real-behav-wg-empty-")
    athena.create_work_group(Name=empty_wg)
    athena.delete_work_group(WorkGroup=empty_wg)
    empty_code, empty_msg = _error(lambda: athena.get_work_group(WorkGroup=empty_wg))
    assert empty_code == "InvalidRequestException", (
        f"expected empty workgroup {empty_wg!r} gone after non-recursive delete, got {empty_code!r}"
    )
    assert empty_msg == "WorkGroup is not found.", empty_msg

    wg_name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=wg_name)

    nq = athena.create_named_query(
        Name=ctx.unique_name("sim2real-behav-nq-"),
        Database="default",
        QueryString="SELECT 1",
        WorkGroup=wg_name,
    )
    named_query_id = nq["NamedQueryId"]
    deleted = False

    def _cleanup():
        if not deleted:
            athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)

    ctx.on_cleanup(_cleanup)

    # Break exactly one thing: delete without acknowledging the named query.
    code, message = _error(lambda: athena.delete_work_group(WorkGroup=wg_name))
    assert code == "InvalidRequestException", (
        f"expected non-recursive delete of a non-empty workgroup to be rejected, got {code!r}"
    )
    expected = f"WorkGroup {wg_name} is not empty"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: workgroup and its named query both still exist.
    still_there = athena.get_work_group(WorkGroup=wg_name)
    assert still_there["WorkGroup"]["Name"] == wg_name, (
        f"expected workgroup {wg_name!r} to survive the rejected delete, "
        f"got {still_there['WorkGroup']['Name']!r}"
    )
    still_named = athena.get_named_query(NamedQueryId=named_query_id)
    assert still_named["NamedQuery"]["NamedQueryId"] == named_query_id, (
        f"expected named query {named_query_id!r} to survive the rejected delete, "
        f"got {still_named['NamedQuery']['NamedQueryId']!r}"
    )

    # Restore (same file): recursive delete of the SAME workgroup succeeds.
    athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)
    deleted = True
    code2, message2 = _error(lambda: athena.get_work_group(WorkGroup=wg_name))
    assert code2 == "InvalidRequestException", (
        f"expected workgroup {wg_name!r} gone after recursive delete, got {code2!r}"
    )
    assert message2 == "WorkGroup is not found.", message2


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

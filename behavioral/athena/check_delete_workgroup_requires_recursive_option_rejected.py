"""delete-workgroup-requires-recursive-option-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-workgroup-requires-recursive-option-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkGroup on a workgroup owning a named query fails InvalidRequestException and the
    workgroup survives until RecursiveDeleteOption=True; an empty workgroup deletes without it."""
    athena = ctx.client("athena")

    # Positive control: an empty workgroup (no dependents) deletes cleanly without
    # RecursiveDeleteOption. Without this, a target that rejects every DeleteWorkGroup
    # call regardless of contents would pass this check identically to a correct one.
    control_wg = ctx.unique_name("sim2real-athena-wg-ctrl-")
    athena.create_work_group(Name=control_wg)
    control_deleted = False

    def _cleanup_control():
        if not control_deleted:
            athena.delete_work_group(WorkGroup=control_wg, RecursiveDeleteOption=True)

    ctx.on_cleanup(_cleanup_control)
    athena.delete_work_group(WorkGroup=control_wg)
    control_deleted = True
    control_gone, control_msg = _error(lambda: athena.get_work_group(WorkGroup=control_wg))
    assert control_gone == "InvalidRequestException", control_gone
    assert control_msg == "WorkGroup is not found.", control_msg

    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg_name)
    nq_id = athena.create_named_query(
        Name=ctx.unique_name("sim2real-nq-"),
        Database="default",
        QueryString="SELECT 1",
        WorkGroup=wg_name,
    )["NamedQueryId"]
    wg_deleted = False

    def _cleanup_wg():
        # RecursiveDeleteOption forces the workgroup delete but does not cascade-delete
        # the named query saved under it, so both are cleaned up independently.
        if not wg_deleted:
            athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)
        from botocore.exceptions import ClientError

        try:
            athena.delete_named_query(NamedQueryId=nq_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException":
                raise

    ctx.on_cleanup(_cleanup_wg)

    code, message = _error(lambda: athena.delete_work_group(WorkGroup=wg_name))
    assert code == "InvalidRequestException", code
    assert message == f"WorkGroup {wg_name} is not empty", message

    # The rejected delete must not have removed the workgroup.
    still_there = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]
    assert still_there["Name"] == wg_name, still_there.get("Name")

    athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)
    wg_deleted = True
    code_after, message_after = _error(lambda: athena.get_work_group(WorkGroup=wg_name))
    assert code_after == "InvalidRequestException", code_after
    assert message_after == "WorkGroup is not found.", message_after


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

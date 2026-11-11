"""workgroup-delete-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "workgroup-delete-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkGroup on a workgroup holding a named query is rejected with InvalidRequestException
    and the workgroup survives, an empty one deletes, and RecursiveDeleteOption=True deletes the
    workgroup while its named query stays retrievable."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=name, Tags=[{"Key": "sim2real", "Value": "workgroup-delete-conflict-rejected"}]
    )

    nq_id = athena.create_named_query(
        Name=ctx.unique_name("sim2real-athena-nq-"),
        Database="default",
        QueryString="SELECT 1",
        WorkGroup=name,
    )["NamedQueryId"]

    def _delete_named_query():
        from botocore.exceptions import ClientError

        try:
            athena.delete_named_query(NamedQueryId=nq_id)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("InvalidRequestException", "ResourceNotFoundException"):
                raise

    ctx.on_cleanup(_delete_named_query)

    code, message = _error(lambda: athena.delete_work_group(WorkGroup=name))
    assert code == "InvalidRequestException", code
    assert message == f"WorkGroup {name} is not empty", message

    # Effect absent: workgroup still exists after the rejected delete.
    wg = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert wg["Name"] == name

    # Positive control, same call shape: an empty sibling workgroup -- no named query,
    # no RecursiveDeleteOption -- deletes cleanly. Without this, "rejects delete when a
    # named query exists" would be indistinguishable from "rejects every DeleteWorkGroup".
    empty_name = ctx.unique_name("sim2real-athena-wg-empty-")
    athena.create_work_group(
        Name=empty_name, Tags=[{"Key": "sim2real", "Value": "workgroup-delete-conflict-rejected"}]
    )
    athena.delete_work_group(WorkGroup=empty_name)
    empty_code, empty_message = _error(lambda: athena.get_work_group(WorkGroup=empty_name))
    assert empty_code == "InvalidRequestException", empty_code
    assert empty_message == "WorkGroup is not found.", empty_message

    athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    code2, message2 = _error(lambda: athena.get_work_group(WorkGroup=name))
    assert code2 == "InvalidRequestException", code2
    assert message2 == "WorkGroup is not found.", message2

    # The named query is NOT cascade-deleted along with its workgroup: RecursiveDeleteOption
    # only permits deleting a non-empty workgroup, it does not remove the named queries that
    # were saved under it. Verify the named query still exists and is unchanged.
    nq = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert nq["NamedQueryId"] == nq_id
    assert nq["WorkGroup"] == name, nq["WorkGroup"]


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

"""named-query-lifecycle-create-get-update-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "named-query-lifecycle-create-get-update-delete"
GROUP = 'named-query'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """NamedQuery supports create -> get -> update -> delete; get-after-delete fails, and
    a further mutation (update) against the deleted id also fails."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-nq-")
    nq_id = athena.create_named_query(
        Name=name,
        Database="default",
        QueryString="SELECT 1",
        Description="v1",
    )["NamedQueryId"]
    ctx.on_cleanup(lambda: _delete_if_present(athena, nq_id))

    got = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert got["Name"] == name
    assert got["QueryString"] == "SELECT 1"
    assert got["Description"] == "v1"

    new_name = ctx.unique_name("sim2real-behav-nq-updated-")
    athena.update_named_query(
        NamedQueryId=nq_id,
        Name=new_name,
        QueryString="SELECT 2",
        Description="v2",
    )

    updated = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert updated["Name"] == new_name
    assert updated["QueryString"] == "SELECT 2"
    assert updated["Description"] == "v2"

    athena.delete_named_query(NamedQueryId=nq_id)

    gone = ("InvalidRequestException", f"NamedQuery: {nq_id} does not exist")
    got = _error(lambda: athena.get_named_query(NamedQueryId=nq_id))
    assert got == gone, f"expected named query gone with {gone}, got {got}"

    update_got = _error(
        lambda: athena.update_named_query(
            NamedQueryId=nq_id,
            Name=new_name,
            QueryString="SELECT 3",
            Description="v3",
        )
    )
    assert update_got == gone, f"expected update on deleted named query to fail with {gone}, got {update_got}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_if_present(athena, nq_id):
    """Teardown: the body deletes the query itself, so an already-gone id is not a failure."""
    from botocore.exceptions import ClientError

    try:
        athena.delete_named_query(NamedQueryId=nq_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

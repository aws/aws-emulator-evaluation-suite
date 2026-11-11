"""named-query-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "named-query-lifecycle"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/Get/Update/DeleteNamedQuery round-trip the exact fields and ListNamedQueries shows the
    query then drops it; after delete, a read and an update on the id fail with the same error."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-nq-")
    nq_id = athena.create_named_query(
        Name=name, Database="default", QueryString="SELECT 1", Description="v1"
    )["NamedQueryId"]
    ctx.on_cleanup(lambda: _delete_if_present(athena, nq_id))

    got = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert got["Name"] == name, f"expected Name={name!r}, got {got['Name']!r}"
    assert got["Database"] == "default", f"expected Database='default', got {got['Database']!r}"
    assert got["QueryString"] == "SELECT 1", f"expected QueryString='SELECT 1', got {got['QueryString']!r}"
    assert got["Description"] == "v1", f"expected Description='v1', got {got['Description']!r}"

    ids = athena.list_named_queries()["NamedQueryIds"]
    assert nq_id in ids, f"expected {nq_id} in ListNamedQueries, got {ids}"

    new_name = name + "-updated"
    athena.update_named_query(
        NamedQueryId=nq_id, Name=new_name, QueryString="SELECT 2", Description="v2"
    )
    got2 = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert got2["Name"] == new_name, f"expected Name={new_name!r}, got {got2['Name']!r}"
    assert got2["QueryString"] == "SELECT 2", f"expected QueryString='SELECT 2', got {got2['QueryString']!r}"
    assert got2["Description"] == "v2", f"expected Description='v2', got {got2['Description']!r}"

    athena.delete_named_query(NamedQueryId=nq_id)
    gone = ("InvalidRequestException", f"NamedQuery: {nq_id} does not exist")
    got = _error(lambda: athena.get_named_query(NamedQueryId=nq_id))
    assert got == gone, f"expected GetNamedQuery on a deleted id to fail with {gone}, got {got!r}"
    ids_after = athena.list_named_queries()["NamedQueryIds"]
    assert nq_id not in ids_after, f"expected {nq_id} absent from ListNamedQueries after delete, got {ids_after}"

    mutation = _error(
        lambda: athena.update_named_query(
            NamedQueryId=nq_id, Name=name, QueryString="SELECT 3", Description="v3"
        )
    )
    assert mutation == gone, f"expected UpdateNamedQuery on a deleted id to fail with {gone}, got {mutation!r}"


def _delete_if_present(athena, nq_id):
    from botocore.exceptions import ClientError

    try:
        athena.delete_named_query(NamedQueryId=nq_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidRequestException":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

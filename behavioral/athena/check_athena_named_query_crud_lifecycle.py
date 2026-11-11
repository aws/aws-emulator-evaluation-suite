"""athena-named-query-crud-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-named-query-crud-lifecycle"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNamedQuery -> UpdateNamedQuery mutates fields -> DeleteNamedQuery removes it,
    and the dead id is both unreadable and unmutatable afterward."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-nq-")

    nq_id = athena.create_named_query(
        Name=name,
        Database="default",
        QueryString="SELECT 1",
        Description="v1",
    )["NamedQueryId"]

    def _cleanup():
        try:
            athena.delete_named_query(NamedQueryId=nq_id)
        except ClientError as exc:
            # Already deleted by the body's own DeleteNamedQuery ("NamedQuery: <id> does not exist").
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup)

    nq = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert nq["Name"] == name, f"expected Name {name!r}, got {nq['Name']!r}"
    assert nq["QueryString"] == "SELECT 1", f"expected QueryString 'SELECT 1', got {nq['QueryString']!r}"
    assert nq["Database"] == "default", f"expected Database 'default', got {nq['Database']!r}"
    assert nq["Description"] == "v1", f"expected Description 'v1', got {nq['Description']!r}"

    updated_name = name + "-v2"
    athena.update_named_query(
        NamedQueryId=nq_id, Name=updated_name, QueryString="SELECT 2", Description="v2"
    )
    nq2 = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert nq2["Name"] == updated_name, f"expected updated Name {updated_name!r}, got {nq2['Name']!r}"
    assert nq2["QueryString"] == "SELECT 2", f"expected updated QueryString 'SELECT 2', got {nq2['QueryString']!r}"
    assert nq2["Description"] == "v2", f"expected updated Description 'v2', got {nq2['Description']!r}"

    ids = athena.list_named_queries()["NamedQueryIds"]
    assert nq_id in ids, f"expected {nq_id} in ListNamedQueries before delete, got {ids}"

    athena.delete_named_query(NamedQueryId=nq_id)

    try:
        athena.get_named_query(NamedQueryId=nq_id)
        raise AssertionError("expected GetNamedQuery on a deleted id to raise")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
        assert message == f"NamedQuery: {nq_id} does not exist", f"unexpected GetNamedQuery message {message!r}"

    try:
        athena.delete_named_query(NamedQueryId=nq_id)
        raise AssertionError("expected a second DeleteNamedQuery on the dead id to raise")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "InvalidRequestException", f"expected InvalidRequestException on re-delete, got {code}"
        assert message == f"NamedQuery: {nq_id} does not exist", f"unexpected re-delete message {message!r}"

    ids_after = athena.list_named_queries()["NamedQueryIds"]
    assert nq_id not in ids_after, f"expected {nq_id} absent from ListNamedQueries after delete, got {ids_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

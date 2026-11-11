"""op-contract-updateNamedQuery."""
from __future__ import annotations

import uuid

CHECK = "op-contract-updateNamedQuery"
GROUP = "error-semantics"
SERVICES = ["athena"]

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp is not None:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(
        f"expected UpdateNamedQuery against a nonexistent NamedQueryId to be rejected, "
        f"but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNamedQuery overwrites Name/Description/QueryString for a fixed NamedQueryId; a bogus id is rejected."""
    athena = ctx.client("athena")

    original_name = ctx.unique_name("sim2real-behav-nq-")
    created = athena.create_named_query(
        Name=original_name,
        Database="default",
        QueryString="SELECT 1",
        Description="original description",
    )
    named_query_id = created["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=named_query_id))

    before = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]
    assert before["Name"] == original_name, f"expected Name={original_name!r}, got {before['Name']!r}"
    assert before["QueryString"] == "SELECT 1", f"expected QueryString='SELECT 1', got {before['QueryString']!r}"
    assert before["Description"] == "original description", (
        f"expected Description='original description', got {before['Description']!r}"
    )

    new_name = ctx.unique_name("sim2real-behav-nq-updated-")
    athena.update_named_query(
        NamedQueryId=named_query_id,
        Name=new_name,
        Description="updated description",
        QueryString="SELECT 2",
    )
    after = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]
    assert after["Name"] == new_name, after
    assert after["QueryString"] == "SELECT 2", after
    assert after["Description"] == "updated description", after
    # NamedQueryId itself is immutable across the update.
    reread_id = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]["NamedQueryId"]
    assert reread_id == named_query_id, f"expected NamedQueryId={named_query_id!r} unchanged, got {reread_id!r}"

    # Error boundary: NamedQueryId that does not exist.
    bogus_id = str(uuid.uuid4())
    code, message = _error(
        lambda: athena.update_named_query(
            NamedQueryId=bogus_id, Name="whatever", QueryString="SELECT 3"
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"NamedQuery: {bogus_id} does not exist", message

    # The real named query must be unaffected by the failed call above.
    still = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]
    assert still["Name"] == new_name, f"expected Name={new_name!r} unaffected, got {still['Name']!r}"
    assert still["QueryString"] == "SELECT 2", f"expected QueryString='SELECT 2' unaffected, got {still['QueryString']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

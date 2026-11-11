"""named-query-client-token-idempotency."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "named-query-client-token-idempotency"
GROUP = 'named-query'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with identical params returns the same id; reuse with different params fails."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-tok-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": "behav-tok"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    token = f"sim2real-behav-tok-{uuid.uuid4().hex}"
    name = ctx.unique_name("sim2real-behav-nq-tok-")

    first = athena.create_named_query(
        Name=name, Database="default", QueryString="SELECT 1", WorkGroup=wg, ClientRequestToken=token
    )
    nq_id = first["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=nq_id))

    second = athena.create_named_query(
        Name=name, Database="default", QueryString="SELECT 1", WorkGroup=wg, ClientRequestToken=token
    )
    assert second["NamedQueryId"] == nq_id, "same token+params must return the same NamedQueryId (idempotent create)"

    # Independent read: idempotent replay must not have created a second resource.
    ids = athena.list_named_queries(WorkGroup=wg)["NamedQueryIds"]
    assert ids.count(nq_id) == 1, f"expected exactly one named query {nq_id} in workgroup, got {ids.count(nq_id)}"

    from botocore.exceptions import ClientError

    try:
        result = athena.create_named_query(
            Name=name, Database="default", QueryString="SELECT 2", WorkGroup=wg, ClientRequestToken=token
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
    else:
        raise AssertionError(
            f"expected reusing the token with different params to be rejected, but it returned {result!r}"
        )
    expected = ("InvalidRequestException", "Idempotent parameters do not match")
    assert got == expected, f"reusing token with different params: expected {expected}, got {got}"

    # Terminal assertion: an independent read (GetNamedQuery) proves the rejected,
    # conflicting-params replay had no effect on the resource the token originally created.
    unchanged = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert unchanged["QueryString"] == "SELECT 1", (
        f"conflicting-params replay must not mutate the original query, got {unchanged['QueryString']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""athena-named-query-client-request-token-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-named-query-client-request-token-idempotent"
GROUP = "idempotency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNamedQuery with a reused ClientRequestToken+params is idempotent; different params are rejected."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-nq-")
    token = ctx.unique_name("sim2real-athena-token-")

    first = athena.create_named_query(
        Name=name, Database="default", QueryString="SELECT 1", ClientRequestToken=token
    )["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=first))

    # Same token + identical params -> same NamedQueryId, no second resource created.
    second = athena.create_named_query(
        Name=name, Database="default", QueryString="SELECT 1", ClientRequestToken=token
    )["NamedQueryId"]
    assert second == first, f"expected reused token+identical params to return {first!r}, got {second!r}"

    ids = athena.list_named_queries()["NamedQueryIds"]
    assert ids.count(first) == 1, f"expected exactly 1 NamedQueryId {first!r} in ListNamedQueries, saw {ids.count(first)}"

    # Same token + DIFFERENT params -> rejected.
    from botocore.exceptions import ClientError

    try:
        athena.create_named_query(
            Name=name, Database="default", QueryString="SELECT 2", ClientRequestToken=token
        )
        raise AssertionError("expected reused token with different params to raise InvalidRequestException")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "InvalidRequestException", f"expected InvalidRequestException reusing token with different params, got {code!r}"
        assert message == "Idempotent parameters do not match", (
            f"unexpected message reusing token with different params: {message!r}"
        )

    # The original named query is unmodified.
    nq = athena.get_named_query(NamedQueryId=first)["NamedQuery"]
    assert nq["QueryString"] == "SELECT 1", f"expected original QueryString 'SELECT 1' unchanged, got {nq['QueryString']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""update-named-query-name-and-query-string."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-named-query-name-and-query-string"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNamedQuery overwrites Name/Description/QueryString for an existing NamedQueryId and rejects an unknown id."""
    athena = ctx.client("athena")

    original_name = ctx.unique_name("sim2real-athena-nq-")
    created = athena.create_named_query(
        Name=original_name,
        Database="default",
        QueryString="SELECT 1",
        Description="v1",
    )
    query_id = created["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=query_id))

    fetched = athena.get_named_query(NamedQueryId=query_id)["NamedQuery"]
    assert fetched["Name"] == original_name, fetched["Name"]
    assert fetched["QueryString"] == "SELECT 1", fetched["QueryString"]
    assert fetched["Description"] == "v1", fetched["Description"]

    # success path: rename, change the SQL text and description; the same NamedQueryId persists.
    updated_name = ctx.unique_name("sim2real-athena-nq-renamed-")
    athena.update_named_query(
        NamedQueryId=query_id,
        Name=updated_name,
        Description="v2",
        QueryString="SELECT 2",
    )
    refetched = athena.get_named_query(NamedQueryId=query_id)["NamedQuery"]
    assert refetched["Name"] == updated_name, refetched["Name"]
    assert refetched["QueryString"] == "SELECT 2", refetched["QueryString"]
    assert refetched["Description"] == "v2", refetched["Description"]
    assert refetched["NamedQueryId"] == query_id, refetched["NamedQueryId"]

    # error boundary: updating a NamedQueryId that does not exist is rejected.
    bogus_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: athena.update_named_query(
        NamedQueryId=bogus_id, Name="whatever", QueryString="SELECT 3"
    ))
    assert code == "InvalidRequestException", code
    assert message == f"NamedQuery: {bogus_id} does not exist", message

    # positive control: original query is unaffected by the failed call above.
    still = athena.get_named_query(NamedQueryId=query_id)["NamedQuery"]
    assert still["Name"] == updated_name, still["Name"]
    assert still["QueryString"] == "SELECT 2", still["QueryString"]


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected UpdateNamedQuery to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

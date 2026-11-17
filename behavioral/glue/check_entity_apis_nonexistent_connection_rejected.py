"""entity-apis-nonexistent-connection-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "entity-apis-nonexistent-connection-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListEntities, DescribeEntity and GetEntityRecords each raise EntityNotFoundException
    naming the connection when ConnectionName refers to no real connection.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_ListEntities.html
    """
    glue = ctx.client("glue")

    # Positive control: Glue itself is reachable and the credentials are healthy, so the
    # refusals below are specific to the missing connection, not a blanket denial.
    healthy = glue.get_databases()
    assert "DatabaseList" in healthy, f"GetDatabases failed on an otherwise-healthy account: {healthy!r}"

    connection_name = ctx.unique_name("sim2real-entityapi-conn-")
    expected = (
        "EntityNotFoundException",
        f"Connection with name {connection_name} in account {ctx.account} is not found",
    )

    list_result = _refusal(lambda: glue.list_entities(ConnectionName=connection_name))
    assert list_result == expected, f"unexpected ListEntities refusal: {list_result!r}"

    describe_result = _refusal(
        lambda: glue.describe_entity(ConnectionName=connection_name, EntityName="Account")
    )
    assert describe_result == expected, f"unexpected DescribeEntity refusal: {describe_result!r}"

    records_result = _refusal(
        lambda: glue.get_entity_records(ConnectionName=connection_name, EntityName="Account", Limit=1)
    )
    assert records_result == expected, f"unexpected GetEntityRecords refusal: {records_result!r}"


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

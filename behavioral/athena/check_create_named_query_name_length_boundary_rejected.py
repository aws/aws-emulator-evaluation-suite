"""create-named-query-name-length-boundary-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-named-query-name-length-boundary-rejected"
GROUP = "representation"
SERVICES = ["athena"]


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNamedQuery accepts a 128-character Name, its documented maximum, and refuses one
    character more with the exact length-constraint message."""
    athena = ctx.client("athena")
    prefix = ctx.unique_name("sim2real-nq-")
    name_at_max = prefix + "x" * (128 - len(prefix))
    assert len(name_at_max) == 128, f"test setup built a {len(name_at_max)}-character name, expected 128"

    nq_id = athena.create_named_query(
        Name=name_at_max, Database="default", QueryString="SELECT 1",
    )["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=nq_id))

    fetched = athena.get_named_query(NamedQueryId=nq_id)["NamedQuery"]
    assert fetched["Name"] == name_at_max, (
        f"expected GetNamedQuery to echo the 128-character Name exactly, got {fetched['Name']!r}"
    )

    name_over_max = name_at_max + "y"
    code, message = _error(
        lambda: athena.create_named_query(
            Name=name_over_max, Database="default", QueryString="SELECT 1",
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for a 129-character Name, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must have length less than or equal to 128"
    ), f"unexpected CreateNamedQuery message for a 129-character Name: {message!r}"

    ids = set()
    for page in athena.get_paginator("list_named_queries").paginate():
        ids.update(page["NamedQueryIds"])
    assert nq_id in ids, f"expected the 128-character named query {nq_id!r} in ListNamedQueries"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

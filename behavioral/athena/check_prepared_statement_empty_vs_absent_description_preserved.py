"""prepared-statement-empty-vs-absent-description-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "prepared-statement-empty-vs-absent-description-preserved"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A single-space prepared-statement Description round-trips; an omitted one stays absent.

    UpdatePreparedStatement without Description keeps it absent, an update with Description
    sets it on the description-less statement, and a new Description replaces a present one.
    """
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-behav-psq-wg-")
    athena.create_work_group(
        Name=wg_name,
        Tags=[{"Key": "sim2real", "Value": "prepared-statement-empty-vs-absent-description"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    with_desc = ctx.unique_name("sim2real_behav_psq_with_")
    without_desc = ctx.unique_name("sim2real_behav_psq_without_")

    # Description has a modeled minimum length of 1, so botocore rejects "" client-side; a single
    # space is the emptiest value the API accepts.
    athena.create_prepared_statement(
        StatementName=with_desc, WorkGroup=wg_name, QueryStatement="SELECT 1", Description=" "
    )
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=with_desc, WorkGroup=wg_name))
    athena.create_prepared_statement(
        StatementName=without_desc, WorkGroup=wg_name, QueryStatement="SELECT 1"
    )
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=without_desc, WorkGroup=wg_name))

    with_desc_stmt = athena.get_prepared_statement(StatementName=with_desc, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert "Description" in with_desc_stmt, f"expected a Description field, got {with_desc_stmt!r}"
    assert with_desc_stmt["Description"] == " ", (
        f"expected Description == ' ', got {with_desc_stmt['Description']!r}"
    )

    without_desc_stmt = athena.get_prepared_statement(StatementName=without_desc, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert "Description" not in without_desc_stmt, (
        f"expected no Description field, got {without_desc_stmt.get('Description')!r}"
    )

    # An update that omits Description must not invent one.
    athena.update_prepared_statement(
        StatementName=without_desc, WorkGroup=wg_name, QueryStatement="SELECT 2"
    )
    updated_without_desc = athena.get_prepared_statement(StatementName=without_desc, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert updated_without_desc["QueryStatement"] == "SELECT 2", (
        f"expected QueryStatement == 'SELECT 2', got {updated_without_desc['QueryStatement']!r}"
    )
    assert "Description" not in updated_without_desc, (
        f"expected no Description field, got {updated_without_desc.get('Description')!r}"
    )

    # An update that names a Description moves the statement from absent to present.
    athena.update_prepared_statement(
        StatementName=without_desc, WorkGroup=wg_name, QueryStatement="SELECT 2", Description=" "
    )
    now_with_desc = athena.get_prepared_statement(StatementName=without_desc, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert now_with_desc.get("Description") == " ", (
        f"expected Description == ' ' after the update, got {now_with_desc.get('Description')!r}"
    )

    # Updating the description-bearing statement can change the value round-trip.
    athena.update_prepared_statement(
        StatementName=with_desc, WorkGroup=wg_name, QueryStatement="SELECT 1", Description="now set"
    )
    updated_with_desc = athena.get_prepared_statement(StatementName=with_desc, WorkGroup=wg_name)[
        "PreparedStatement"
    ]
    assert updated_with_desc["Description"] == "now set", (
        f"expected Description == 'now set', got {updated_with_desc['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""e2e-glossary-term-association-workflow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-glossary-term-association-workflow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create a glossary and term, associate it to a catalog asset (a table), then
    delete the term and observe the association is actually gone from the asset --
    not just that each individual call returned success."""
    glue = ctx.client("glue")
    sts = ctx.client("sts")

    glossary_name = ctx.unique_name("sim2real-behav-e2egloss-")
    glossary = glue.create_glossary(Name=glossary_name)
    glossary_id = glossary["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary_id))

    term = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id,
        Name="RevenueRecognitionDate",
        ShortDescription="The date revenue is recognized per accounting policy",
    )
    term_id = term["Id"]

    db_name = ctx.unique_name("sim2real-behav-e2edb-")
    table_name = ctx.unique_name("sim2real-behav-e2etbl-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-behav-check": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": f"s3://sim2real-behav-placeholder/{table_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    account_id = sts.get_caller_identity()["Account"]
    asset_arn = f"arn:aws:glue:{ctx.region}:{account_id}:table/{db_name}/{table_name}"

    # Newly-created catalog tables are indexed as business-context "assets"
    # asynchronously; a freshly created table can transiently 404 on
    # AssociateGlossaryTerms until that indexing catches up.
    assoc = _poll_associate(ctx, asset_arn, term_id)
    assert term_id in assoc["GlossaryTerms"], (
        f"AssociateGlossaryTerms returned GlossaryTerms={assoc['GlossaryTerms']!r}, "
        f"expected {term_id!r} to be present"
    )

    asset_after_associate = glue.get_asset(Identifier=asset_arn)
    assert term_id in asset_after_associate.get(
        "GlossaryTerms", []
    ), "AssociateGlossaryTerms reported success but the asset does not list the term"

    # Now explicitly disassociate the term (the documented workflow for removing an
    # association) and confirm it's gone from the asset, then delete the term itself
    # and confirm it's gone entirely -- not just that each call returned success.
    glue.disassociate_glossary_terms(AssetIdentifier=asset_arn, GlossaryTermIdentifiers=[term_id])

    asset_after_disassociate = _poll_disassociated(ctx, asset_arn, term_id)
    assert term_id not in asset_after_disassociate.get(
        "GlossaryTerms", []
    ), "DisassociateGlossaryTerms reported success but the asset still lists the term"

    glue.delete_glossary_term(Identifier=term_id)

    code, message = _error(lambda: glue.get_glossary_term(Identifier=term_id))
    assert code == "EntityNotFoundException", (
        f"expected GetGlossaryTerm on the deleted term to be EntityNotFoundException, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_disassociated(ctx, asset_arn, term_id, timeout_s=120.0, interval_s=5.0):
    import time as _time

    glue = ctx.client("glue")
    deadline = _time.monotonic() + timeout_s
    last = None
    while _time.monotonic() < deadline:
        last = glue.get_asset(Identifier=asset_arn)
        if term_id not in last.get("GlossaryTerms", []):
            return last
        _time.sleep(interval_s)
    return last


def _poll_associate(ctx, asset_arn, term_id, timeout_s=300.0, interval_s=10.0):
    import time as _time

    from botocore.exceptions import ClientError

    glue = ctx.client("glue")
    deadline = _time.monotonic() + timeout_s
    last_exc = None
    while _time.monotonic() < deadline:
        try:
            return glue.associate_glossary_terms(AssetIdentifier=asset_arn, GlossaryTermIdentifiers=[term_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise
            last_exc = exc
            _time.sleep(interval_s)
    raise AssertionError(f"asset {asset_arn} never became associable within {timeout_s}s: {last_exc}")


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


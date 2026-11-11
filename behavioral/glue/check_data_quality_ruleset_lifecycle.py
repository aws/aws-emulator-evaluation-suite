"""data-quality-ruleset-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-quality-ruleset-lifecycle"
GROUP = 'data-quality'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """data_quality_ruleset create -> get -> update -> list -> delete against a target table."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    ruleset_name = ctx.unique_name("sim2real-behav-dqr-")
    glue.create_data_quality_ruleset(
        Name=ruleset_name,
        Description="v1",
        Ruleset="Rules = [ ColumnCount > 0 ]",
        TargetTable={"TableName": tbl_name, "DatabaseName": db_name},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: glue.delete_data_quality_ruleset(Name=ruleset_name)))

    rs = glue.get_data_quality_ruleset(Name=ruleset_name)
    assert rs["Name"] == ruleset_name, f"GetDataQualityRuleset returned wrong Name: {rs}"
    assert "ColumnCount" in rs["Ruleset"], f"ruleset body not persisted: {rs}"
    assert rs["TargetTable"]["TableName"] == tbl_name, f"target table not persisted: {rs}"

    glue.update_data_quality_ruleset(
        Name=ruleset_name,
        Description="v2",
        Ruleset="Rules = [ ColumnCount > 1 ]",
    )
    updated = glue.get_data_quality_ruleset(Name=ruleset_name)
    assert updated["Description"] == "v2", f"UpdateDataQualityRuleset lost Description: {updated}"
    assert "ColumnCount > 1" in updated["Ruleset"], (
        f"UpdateDataQualityRuleset lost the new rule body: {updated}"
    )

    names = {r["Name"] for r in glue.list_data_quality_rulesets()["Rulesets"]}
    assert ruleset_name in names, "ruleset missing from ListDataQualityRulesets"

    glue.delete_data_quality_ruleset(Name=ruleset_name)
    try:
        glue.get_data_quality_ruleset(Name=ruleset_name)
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after DeleteDataQualityRuleset, got {code}"
    )
    expected = f"Cannot find Data Quality Ruleset in account {ctx.account} with name {ruleset_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    try:
        glue.update_data_quality_ruleset(Name=ruleset_name, Description="v3")
        mutate_code, mutate_message = None, None
    except ClientError as exc:
        mutate_code = exc.response.get("Error", {}).get("Code")
        mutate_message = exc.response.get("Error", {}).get("Message")
    assert mutate_code == "EntityNotFoundException", (
        f"expected UpdateDataQualityRuleset on a deleted ruleset to fail with "
        f"EntityNotFoundException, got {mutate_code}"
    )
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"

def _ignore_not_found(fn):
    """Teardown: the check deletes the ruleset itself, so not-found here is success."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

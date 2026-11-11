"""deploy-datacatalog-cloudformation-queryable."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-datacatalog-cloudformation-queryable"
GROUP = "deploy"
SERVICES = ["athena"]

_DC_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  CatalogName:
    Type: String
  GlueCatalogId:
    Type: String
Resources:
  DC:
    Type: AWS::Athena::DataCatalog
    Properties:
      Name: !Ref CatalogName
      Type: GLUE
      Parameters:
        catalog-id: !Ref GlueCatalogId
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A GLUE AWS::Athena::DataCatalog stack yields a CREATE_COMPLETE catalog whose ListDatabases
    shows a separately created Glue database; deleting the stack makes GetDataCatalog reject it
    and drops it from ListDataCatalogs."""
    sts = ctx.client("sts")
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")
    athena = ctx.client("athena")

    account_id = sts.get_caller_identity()["Account"]

    db_name = ctx.unique_name("sim2real_athena_dc_db_").lower().replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_database(Name=db_name)))

    stack_name = ctx.unique_name("sim2real-athena-dc-stack-")
    catalog_name = ctx.unique_name("sim2real-athena-dc-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_DC_TEMPLATE,
        Parameters=[
            {"ParameterKey": "CatalogName", "ParameterValue": catalog_name},
            {"ParameterKey": "GlueCatalogId", "ParameterValue": account_id},
        ],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    dc = athena.get_data_catalog(Name=catalog_name)["DataCatalog"]
    assert dc["Type"] == "GLUE", f"expected Type GLUE, got {dc['Type']}"
    assert dc["Status"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {dc['Status']}"

    databases = athena.list_databases(CatalogName=catalog_name)["DatabaseList"]
    names = {d["Name"] for d in databases}
    assert db_name in names, f"{db_name} missing from {sorted(names)}"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: athena.get_data_catalog(Name=catalog_name))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException on GetDataCatalog after stack delete, got {code}"
    )
    expected = f"DataCatalog {catalog_name} was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    remaining = [c["CatalogName"] for c in athena.list_data_catalogs()["DataCatalogsSummary"]]
    assert catalog_name not in remaining, f"{catalog_name} still listed after stack delete: {remaining}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its ClientError (code, message), or fail if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

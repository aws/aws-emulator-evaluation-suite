"""integration-table-properties-blob-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "integration-table-properties-blob-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64-encoded configuration blob written via CreateIntegrationTableProperties
    (TargetTableConfig.TargetTableName) is returned byte-identical by
    GetIntegrationTableProperties, not truncated or re-encoded."""
    glue = ctx.client("glue")
    sts = ctx.client("sts")

    db_name = ctx.unique_name("sim2real-behav-itpdb-")
    table_name = ctx.unique_name("sim2real-behav-itptbl-")
    glue.create_database(DatabaseInput={"Name": db_name})
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
    # Per the API docs: to set TargetTableConfig, ResourceArn must be the AWS Glue
    # *database* ARN (not the table ARN); TableName then identifies which table
    # within that database the properties apply to.
    resource_arn = f"arn:aws:glue:{ctx.region}:{account_id}:database/{db_name}"

    # TargetTableName is validated against a table-identifier pattern (rejects
    # base64's '+', '/', '='), and PartitionSpec's ConversionSpec/FunctionSpec are
    # closed enums -- so the byte-blob is carried in PartitionSpec.FieldName, the
    # one free-text field, with FunctionSpec="identity" (no ConversionSpec needed).
    raw_blob = os.urandom(72)
    encoded_blob = base64.b64encode(raw_blob).decode("ascii")
    assert len(encoded_blob) <= 128, f"test blob base64 length {len(encoded_blob)} exceeds the 128-char FieldName budget"

    glue.create_integration_table_properties(
        ResourceArn=resource_arn,
        TableName=table_name,
        TargetTableConfig={
            "UnnestSpec": "FULL",
            "TargetTableName": table_name.replace("-", "_"),
            "PartitionSpec": [{"FieldName": encoded_blob, "FunctionSpec": "identity"}],
        },
    )
    ctx.on_cleanup(
        lambda: glue.delete_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)
    )

    fetched = _poll_get_props(ctx, resource_arn, table_name)
    target_cfg = fetched["TargetTableConfig"]
    assert target_cfg["UnnestSpec"] == "FULL", f"expected UnnestSpec FULL, got {target_cfg.get('UnnestSpec')!r}"
    part_spec = target_cfg["PartitionSpec"][0]
    assert part_spec["FieldName"] == encoded_blob, (
        f"base64 blob not preserved byte-identical (FieldName): expected {encoded_blob!r}, got {part_spec['FieldName']!r}"
    )
    assert part_spec["FunctionSpec"] == "identity", f"expected FunctionSpec identity, got {part_spec.get('FunctionSpec')!r}"

    # Round-trip decodes back to the exact original bytes.
    decoded = base64.b64decode(part_spec["FieldName"])
    assert decoded == raw_blob, f"decoded round-trip bytes {decoded!r} != original {raw_blob!r}"


def _poll_get_props(ctx, resource_arn, table_name, timeout_s=90.0, interval_s=5.0):
    import time as _time

    from botocore.exceptions import ClientError

    glue = ctx.client("glue")
    deadline = _time.monotonic() + timeout_s
    last_exc = None
    while _time.monotonic() < deadline:
        try:
            return glue.get_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise
            last_exc = exc
            _time.sleep(interval_s)
    raise AssertionError(f"integration table properties never became gettable within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

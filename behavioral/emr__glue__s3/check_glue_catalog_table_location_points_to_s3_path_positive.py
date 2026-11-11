"""glue-catalog-table-location-points-to-s3-path-positive."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glue-catalog-table-location-points-to-s3-path-positive"
GROUP = "resource-binding"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Glue Data Catalog table's StorageDescriptor.Location matches the registered S3 URI."""
    bucket = _create_bucket(ctx)
    location = f"s3://{bucket}/warehouse/events/"

    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-glue-db-").replace("-", "_")
    glue.create_database(
        DatabaseInput={"Name": db_name}, Tags={"sim2real": "emr-glue-s3"}
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_glue_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "bigint"},
                    {"Name": "event_type", "Type": "string"},
                ],
                "Location": location,
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                },
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    table = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    reported_location = table["StorageDescriptor"]["Location"]
    assert reported_location == location, (
        f"expected StorageDescriptor.Location {location!r}, got {reported_location!r}"
    )
    reported_columns = {c["Name"] for c in table["StorageDescriptor"]["Columns"]}
    assert reported_columns == {"id", "event_type"}, (
        f"expected columns {{'id', 'event_type'}}, got {reported_columns}"
    )


def _bucket_region_kwargs(ctx):
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-s3-")
    s3.create_bucket(Bucket=name, **_bucket_region_kwargs(ctx))

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

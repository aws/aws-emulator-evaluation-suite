"""Transform stage, shipped as its OWN directory asset.

Reads the extract stage's manifest, digests every record with the module this asset carried, writes
the curated partition object, and registers that partition in the Glue catalog by cloning the
table's own StorageDescriptor — so the catalog entry the check reads back is the table's schema with
the partition's location, not a hand-built guess.

Prints the structured line a CloudWatch Logs metric filter counts into the custom metric the alarm
watches.
"""

import json
import os

import boto3

from vendor import sim2real_records

TOKEN = "SIM2REAL_CURATED"

_s3 = boto3.client("s3")
_glue = boto3.client("glue")


def handler(event, context):
    bucket = os.environ["DATA_BUCKET"]
    database = os.environ["GLUE_DATABASE"]
    table = os.environ["GLUE_TABLE"]
    prefix = os.environ.get("CURATED_PREFIX", "curated/")
    stage = os.environ.get("STAGE", "alpha")
    batch = event["batch"]

    manifest = json.loads(
        _s3.get_object(Bucket=bucket, Key=event["manifest"])["Body"].read().decode("utf-8")
    )
    rows = [
        dict(record, digest=sim2real_records.digest(record), stage=stage)
        for record in manifest["records"]
    ]
    location = f"{prefix}batch={batch}/"
    object_key = location + "part-0.json"
    _s3.put_object(
        Bucket=bucket,
        Key=object_key,
        Body=("\n".join(json.dumps(row) for row in rows)).encode("utf-8"),
    )

    descriptor = dict(_glue.get_table(DatabaseName=database, Name=table)["Table"]["StorageDescriptor"])
    descriptor["Location"] = f"s3://{bucket}/{location}"
    try:
        _glue.create_partition(
            DatabaseName=database,
            TableName=table,
            PartitionInput={"Values": [batch], "StorageDescriptor": descriptor},
        )
    except _glue.exceptions.AlreadyExistsException:
        pass

    print(
        json.dumps(
            {
                "token": TOKEN,
                "batch": batch,
                "object": object_key,
                "rows": len(rows),
                "stage": stage,
                "transformer": sim2real_records.VERSION,
            }
        ),
        flush=True,
    )
    return {
        "object": object_key,
        "rows": len(rows),
        "partition": batch,
        "stage": stage,
        "transformer": sim2real_records.VERSION,
    }

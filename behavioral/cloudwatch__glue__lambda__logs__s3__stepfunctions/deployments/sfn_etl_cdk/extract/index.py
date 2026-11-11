"""Extract stage, shipped as a DIRECTORY asset (see vendor/sim2real_records.py).

Reads the raw JSON-lines object the execution names, parses it with the module the asset carried,
and writes a manifest object the transform stage consumes. Returns the record count, which is what
the state machine's Choice branches on.
"""

import json
import os

import boto3

from vendor import sim2real_records

TOKEN = "SIM2REAL_EXTRACTED"

_s3 = boto3.client("s3")


def handler(event, context):
    bucket = event["bucket"]
    key = event["key"]
    batch = event["batch"]
    body = _s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8", "replace")
    records = sim2real_records.parse(body)
    manifest_key = os.environ.get("MANIFEST_PREFIX", "manifests/") + batch + ".json"
    _s3.put_object(
        Bucket=bucket,
        Key=manifest_key,
        Body=json.dumps(
            {"batch": batch, "records": records, "parser": sim2real_records.VERSION}
        ).encode("utf-8"),
    )
    print(
        json.dumps(
            {
                "token": TOKEN,
                "batch": batch,
                "count": len(records),
                "manifest": manifest_key,
                "parser": sim2real_records.VERSION,
            }
        ),
        flush=True,
    )
    return {
        "bucket": bucket,
        "manifest": manifest_key,
        "count": len(records),
        "parser": sim2real_records.VERSION,
        "packaged_from": sim2real_records.__file__,
    }

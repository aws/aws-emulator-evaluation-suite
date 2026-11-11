"""describe-import-not-found-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-import-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeImport on a just-started import returns its ARN with status IN_PROGRESS or COMPLETED, while an
    import ARN differing only in the id's last character raises ImportNotFoundException with the exact message.
    """
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-dinf-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    key_prefix = "import-data/"
    s3.put_object(
        Bucket=bucket,
        Key=f"{key_prefix}items.json",
        Body=json.dumps({"Item": {"pk": {"S": "row-1"}}}).encode("utf-8"),
    )

    target_table = ctx.unique_name("sim2real-behav-dinf-tbl-")
    import_desc = ddb.import_table(
        S3BucketSource={"S3Bucket": bucket, "S3KeyPrefix": key_prefix},
        InputFormat="DYNAMODB_JSON",
        TableCreationParameters={
            "TableName": target_table,
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "BillingMode": "PAY_PER_REQUEST",
        },
    )["ImportTableDescription"]
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, target_table))
    real_arn = import_desc["ImportArn"]
    assert import_desc["ImportStatus"] in ("IN_PROGRESS", "COMPLETED"), import_desc

    # Positive control: DescribeImport -- an operation independent of the
    # ImportTable call that created it -- succeeds for the real import.
    described = ddb.describe_import(ImportArn=real_arn)["ImportTableDescription"]
    assert described["ImportArn"] == real_arn, f"expected {real_arn}, got {described['ImportArn']}"
    assert described["ImportStatus"] in ("IN_PROGRESS", "COMPLETED"), described

    # A well-formed ARN that was never created: perturb only the import id's
    # trailing character, preserving the id's shape so the request reaches the
    # not-found lookup instead of failing shape validation first.
    fake_arn = real_arn[:-1] + ("0" if real_arn[-1] != "0" else "1")
    assert fake_arn != real_arn, f"perturbation produced the real ARN unchanged: {fake_arn}"

    code, message = _error(lambda: ddb.describe_import(ImportArn=fake_arn))
    assert code == "ImportNotFoundException", f"expected ImportNotFoundException, got {code}"
    expected_message = f"Import not found: Import with arn: {fake_arn} doesn't exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

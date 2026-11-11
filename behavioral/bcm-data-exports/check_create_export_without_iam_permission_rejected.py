"""create-export-without-iam-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-export-without-iam-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-data-exports"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller with no IAM permissions gets AccessDeniedException; nothing is created."""
    bdx = ctx.client("bcm-data-exports")
    bucket = _create_export_bucket(ctx)
    restricted, user_name = _restricted_client(ctx)

    bad_name = ctx.unique_name("sim2real-bcmde-denied-")
    code, message = _error(lambda: restricted.create_export(
        Export=_export_payload(ctx, bad_name, bucket, "exports/")
    ))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    # bcm-data-exports is a region-pinned control plane: the export ARN is us-east-1 whatever
    # region the client is configured with (see the bucket policy below).
    account = _account_id(ctx)
    expected_message = (
        f"User: arn:aws:iam::{account}:user/{user_name} is not authorized to perform: "
        f"bcm-data-exports:CreateExport on resource: "
        f"arn:aws:bcm-data-exports:us-east-1:{account}:export/* because no "
        f"identity-based policy allows the bcm-data-exports:CreateExport action"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    names = {e["ExportName"] for e in _list_all_exports(bdx)}
    assert bad_name not in names, f"denied export {bad_name!r} appeared in ListExports: {names}"

    # Positive control: the default (privileged) caller succeeds.
    good_name = ctx.unique_name("sim2real-bcmde-export-")
    arn = _create_export(ctx, bdx, _export_payload(ctx, good_name, bucket, "exports/"))
    got_name = bdx.get_export(ExportArn=arn)["Export"]["Name"]
    assert got_name == good_name, f"expected GetExport Name {good_name!r}, got {got_name!r}"


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _restricted_client(ctx):
    """Create a brand-new, zero-permission IAM user; return a bcm-data-exports client signed as it
    and the user's name."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-bcmde-noperm-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id, secret_key = key["AccessKeyId"], key["SecretAccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))
    creds = {"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_key}

    deadline = time.monotonic() + 30.0
    last_exc = None
    sts = ctx.client("sts", creds=creds)
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    else:
        raise AssertionError(f"new IAM credentials never became usable: {last_exc}")

    return ctx.client("bcm-data-exports", creds=creds), user_name


def _list_all_exports(bdx):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = bdx.list_exports(**kwargs)
        out.extend(resp.get("Exports", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_export_bucket(ctx, allow_delivery=True):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bcmde-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    if allow_delivery:
        account = _account_id(ctx)
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "EnableAWSDataExportsToWriteToS3",
                "Effect": "Allow",
                "Principal": {"Service": ["bcm-data-exports.amazonaws.com"]},
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    # bcm-data-exports is a region-pinned control plane, so the export ARN is
                    # always us-east-1
                    # regardless of ctx.region.
                    "ArnLike": {"aws:SourceArn": f"arn:aws:bcm-data-exports:us-east-1:{account}:export/*"},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }],
        }
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    return bucket


def _export_payload(ctx, name, bucket, prefix, query_statement=None, table_configurations=None,
                     frequency="SYNCHRONOUS", description="sim2real behavioral check export"):
    data_query = {
        "QueryStatement": query_statement or (
            "SELECT identity_line_item_id, line_item_product_code, line_item_unblended_cost "
            "FROM COST_AND_USAGE_REPORT"
        )
    }
    if table_configurations is not None:
        data_query["TableConfigurations"] = table_configurations
    return {
        "Name": name,
        "Description": description,
        "DataQuery": data_query,
        "DestinationConfigurations": {
            "S3Destination": {
                "S3Bucket": bucket,
                "S3Prefix": prefix,
                "S3Region": ctx.region,
                "S3OutputConfigurations": {
                    "OutputType": "CUSTOM",
                    "Format": "TEXT_OR_CSV",
                    "Compression": "GZIP",
                    "Overwrite": "OVERWRITE_REPORT",
                },
            }
        },
        "RefreshCadence": {"Frequency": frequency},
    }


def _create_export(ctx, bdx, export_payload):
    resp = bdx.create_export(Export=export_payload)
    arn = resp["ExportArn"]

    def _cleanup():
        from botocore.exceptions import ClientError
        try:
            bdx.delete_export(ExportArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

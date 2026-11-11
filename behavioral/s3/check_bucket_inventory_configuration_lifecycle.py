"""bucket-inventory-configuration-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-inventory-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]

_NO_SUCH_CONFIGURATION_MESSAGE = "The specified configuration does not exist."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Put creates a named inventory config visible via List/Get; Delete removes it from both."""
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    src_bucket = ctx.unique_name("sim2real-inv-src-")
    dst_bucket = ctx.unique_name("sim2real-inv-dst-")
    _create_bucket(s3, ctx, src_bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=src_bucket))
    _create_bucket(s3, ctx, dst_bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=dst_bucket))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InventoryDestPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{dst_bucket}/*",
                "Condition": {
                    "ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{src_bucket}"},
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    },
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=dst_bucket, Policy=json.dumps(policy))

    inv_id = ctx.unique_name("invcfg-")
    inv_cfg = {
        "Destination": {
            "S3BucketDestination": {
                "Bucket": f"arn:aws:s3:::{dst_bucket}",
                "Format": "CSV",
            }
        },
        "IsEnabled": True,
        "Id": inv_id,
        "IncludedObjectVersions": "Current",
        "Schedule": {"Frequency": "Daily"},
    }
    s3.put_bucket_inventory_configuration(Bucket=src_bucket, Id=inv_id, InventoryConfiguration=inv_cfg)

    got = s3.get_bucket_inventory_configuration(Bucket=src_bucket, Id=inv_id)
    assert got["InventoryConfiguration"]["Id"] == inv_id
    assert got["InventoryConfiguration"]["IsEnabled"] is True

    listed = s3.list_bucket_inventory_configurations(Bucket=src_bucket)
    ids = [c["Id"] for c in listed.get("InventoryConfigurationList", [])]
    assert inv_id in ids, f"expected {inv_id} in {ids}"

    s3.delete_bucket_inventory_configuration(Bucket=src_bucket, Id=inv_id)

    code, message = _client_error(lambda: s3.get_bucket_inventory_configuration(Bucket=src_bucket, Id=inv_id))
    assert code == "NoSuchConfiguration", f"expected NoSuchConfiguration after delete, got {code}"
    assert message == _NO_SUCH_CONFIGURATION_MESSAGE, f"unexpected message {message!r}"

    listed_after = s3.list_bucket_inventory_configurations(Bucket=src_bucket)
    ids_after = [c["Id"] for c in listed_after.get("InventoryConfigurationList", [])]
    assert inv_id not in ids_after, f"config {inv_id} still listed after delete: {ids_after}"

    # Measured, not assumed: unlike CloudWatch's mostly-idempotent delete family,
    # a second DeleteBucketInventoryConfiguration on an already-gone id enforces a
    # genuine not-found precondition rather than a silent no-op.
    redelete_code, redelete_message = _client_error(
        lambda: s3.delete_bucket_inventory_configuration(Bucket=src_bucket, Id=inv_id)
    )
    assert redelete_code == "NoSuchConfiguration", (
        f"expected a second delete to report NoSuchConfiguration, got {redelete_code}"
    )
    assert redelete_message == _NO_SUCH_CONFIGURATION_MESSAGE, f"unexpected message {redelete_message!r}"
    still_gone = s3.list_bucket_inventory_configurations(Bucket=src_bucket)
    still_gone_ids = [c["Id"] for c in still_gone.get("InventoryConfigurationList", [])]
    assert inv_id not in still_gone_ids, f"double-delete resurrected {inv_id}: {still_gone_ids}"


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

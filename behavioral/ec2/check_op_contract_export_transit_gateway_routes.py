"""op-contract-export-transit-gateway-routes."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-export-transit-gateway-routes"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportTransitGatewayRoutes writes a real JSON export of a transit gateway route
    table to the target S3 bucket, and honors the DryRun permission-check contract."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")

    tgw_name = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=tgw_name,
        Options={"AutoAcceptSharedAttachments": "disable", "DefaultRouteTableAssociation": "enable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": tgw_name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    _wait_for(lambda: _tgw_available(ec2, tgw_id), timeout_s=180)

    tgw = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
    rtb_id = tgw["Options"]["AssociationDefaultRouteTableId"]

    bucket = ctx.unique_name("sim2real-tgwroutes-").lower().replace("_", "-")
    # us-east-1 is the one region S3 rejects a LocationConstraint for; this is S3's own
    # CreateBucket contract, not a check-side region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "Name", "Value": bucket}]})

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    # --- success path: export completes and reports a real s3:// location in-bucket ---
    resp = ec2.export_transit_gateway_routes(TransitGatewayRouteTableId=rtb_id, S3Bucket=bucket)
    s3_location = resp["S3Location"]
    assert s3_location.startswith(f"s3://{bucket}/"), (
        f"expected S3Location under s3://{bucket}/, got {s3_location!r}"
    )

    key = s3_location[len(f"s3://{bucket}/"):]
    _wait_for(lambda: _object_exists(s3, bucket, key), timeout_s=60)

    # --- error boundary: DryRun permission-check contract ---
    code, message = _error(lambda: ec2.export_transit_gateway_routes(
        TransitGatewayRouteTableId=rtb_id, S3Bucket=bucket, DryRun=True
    ))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, message


def _tgw_available(ec2: Any, tgw_id: str) -> bool:
    tgw = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
    return tgw["State"] == "available"


def _object_exists(s3: Any, bucket: str, key: str) -> bool:
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except Exception:
        return False


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError("condition not met within timeout")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""put-delivery-destination-name-over-sixty-characters-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-delivery-destination-name-over-sixty-characters-rejected"
GROUP = "log-delivery"
SERVICES = ["logs", "s3"]

#: PutDeliveryDestination for an S3 bucket is accepted only in us-east-1.
_LOGS_REGION = "us-east-1"


def _error(fn):
    """The (code, message) of the AWS error `fn` raised. An unexpected SUCCESS raises too."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - botocore ClientError carries .response
        resp = getattr(exc, "response", None)
        if not resp:
            raise
        return resp["Error"]["Code"], resp["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _delete_destination_if_present(logs, name) -> None:
    try:
        logs.delete_delivery_destination(name=name)
    except Exception as exc:  # noqa: BLE001 - botocore ClientError carries .response
        resp = getattr(exc, "response", None)
        if not resp or resp["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s) in {bucket}: {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """PutDeliveryDestination refuses a name over the documented 60-character maximum, while a
    60-character name for the identical destination succeeds.
    """
    logs = ctx.client("logs", region=_LOGS_REGION)
    s3 = ctx.client("s3", region=_LOGS_REGION)

    bucket = ctx.unique_name("sim2real-behav-pdd-").lower()
    s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    dest_config = {"destinationResourceArn": f"arn:aws:s3:::{bucket}"}

    # positive control: a name at exactly the documented maximum length succeeds
    ok_name = (ctx.unique_name("sim2real-behav-pdd-") + "a" * 60)[:60]
    assert len(ok_name) == 60, f"the control name must be exactly 60 characters, got {len(ok_name)}"
    ok = logs.put_delivery_destination(
        name=ok_name, outputFormat="json", deliveryDestinationConfiguration=dest_config,
        tags={"sim2real": CHECK},
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: _delete_destination_if_present(logs, ok_name))
    assert ok["name"] == ok_name, f"PutDeliveryDestination must echo the 60-character name, got {ok['name']!r}"

    # one character over the documented maximum is refused
    bad_name = ok_name[:59] + "bb"
    assert len(bad_name) == 61, f"the refused name must be exactly 61 characters, got {len(bad_name)}"
    try:
        code, message = _error(lambda: logs.put_delivery_destination(
            name=bad_name, outputFormat="json", deliveryDestinationConfiguration=dest_config,
            tags={"sim2real": CHECK}))
    except AssertionError:
        # Accepted instead of refused: remove what it created before reporting the mismatch.
        ctx.on_cleanup(lambda: _delete_destination_if_present(logs, bad_name))
        raise
    expected = ("ValidationException",
               "1 validation error detected: Value at 'name' failed to satisfy constraint: "
               "Member must have length less than or equal to 60")
    assert (code, message) == expected, f"expected {expected!r}, got {(code, message)!r}"

    # the refused call registered no destination to find later
    names = {d["name"] for page in logs.get_paginator("describe_delivery_destinations").paginate()
             for d in page["deliveryDestinations"]}
    assert bad_name not in names, f"a refused PutDeliveryDestination must not register {bad_name!r}"
    assert ok_name in names, f"the control destination {ok_name!r} must still be registered"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""delivery-source-lifecycle."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delivery-source-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDeliverySource creates a source visible in DescribeDeliverySources and
    GetDeliverySource, removed by DeleteDeliverySource."""
    logs = ctx.client("logs")

    bucket_name, bucket_arn = _create_bucket(ctx)
    source_name = ctx.unique_name("sim2real-behav-dsrc-")

    put_resp = logs.put_delivery_source(
        name=source_name, resourceArn=bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_source(name=source_name)))
    assert put_resp["deliverySource"]["name"] == source_name
    assert put_resp["deliverySource"]["logType"] == "S3_SERVER_ACCESS_LOGS"
    assert bucket_arn in put_resp["deliverySource"]["resourceArns"]

    got = logs.get_delivery_source(name=source_name)
    assert got["deliverySource"]["name"] == source_name
    assert got["deliverySource"]["arn"] == put_resp["deliverySource"]["arn"]

    described = _collect_all(logs.describe_delivery_sources, "deliverySources")
    names = {s["name"] for s in described}
    assert source_name in names, f"{source_name} missing from DescribeDeliverySources: {names}"

    logs.delete_delivery_source(name=source_name)

    code, message = _expect_error(lambda: logs.get_delivery_source(name=source_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery Source does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    described_after = _collect_all(logs.describe_delivery_sources, "deliverySources")
    assert source_name not in {s["name"] for s in described_after}, (
        "delivery source still listed after DeleteDeliverySource"
    )


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _collect_all(call, resp_key: str, **kwargs) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = call(**params)
        items.extend(resp.get(resp_key, []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-dsrc-b-").lower().replace("_", "-")
    region = ctx.region
    if region and region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    else:
        s3.create_bucket(Bucket=name)
    ctx.on_cleanup(lambda: _safe_call(lambda: s3.delete_bucket(Bucket=name)))
    return name, f"arn:aws:s3:::{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

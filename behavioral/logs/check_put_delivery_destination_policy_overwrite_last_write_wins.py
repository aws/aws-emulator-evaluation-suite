"""put-delivery-destination-policy-overwrite-last-write-wins."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-delivery-destination-policy-overwrite-last-write-wins"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two sequential PutDeliveryDestinationPolicy calls with different documents
    converge to the latest document with no merge/corruption of the earlier one."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-ddow").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    dest_name = ctx.unique_name("sim2real-behav-dd-")
    dest = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="S3",
        deliveryDestinationConfiguration={"destinationResourceArn": bucket_arn},
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    doc_a = _policy_doc(account_id, dest["arn"], sid="AllowLogDeliveryActionsA")
    doc_b = _policy_doc(account_id, dest["arn"], sid="AllowLogDeliveryActionsB")

    logs.put_delivery_destination_policy(
        deliveryDestinationName=dest_name, deliveryDestinationPolicy=json.dumps(doc_a)
    )
    # Poll until the first write is durably visible before issuing the second write,
    # instead of guessing at a fixed propagation delay.
    _poll_until(
        lambda: _get_stored_sids(logs, dest_name),
        lambda sids: sids == {"AllowLogDeliveryActionsA"},
        timeout_s=30.0,
        interval_s=1.0,
    )

    logs.put_delivery_destination_policy(
        deliveryDestinationName=dest_name, deliveryDestinationPolicy=json.dumps(doc_b)
    )
    ctx.on_cleanup(lambda: _delete_policy_best_effort(logs, dest_name))

    sids = _poll_until(
        lambda: _get_stored_sids(logs, dest_name),
        lambda sids: sids == {"AllowLogDeliveryActionsB"},
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert sids == {"AllowLogDeliveryActionsB"}, (
        f"expected only the latest policy document to survive, got Sids={sids}"
    )


def _get_stored_sids(logs, dest_name: str) -> set[str]:
    stored = json.loads(
        logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)["policy"][
            "deliveryDestinationPolicy"
        ]
    )
    return {stmt["Sid"] for stmt in stored["Statement"]}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _policy_doc(account_id: str, dest_arn: str, sid: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "logs:CreateDelivery",
                "Resource": dest_arn,
            }
        ],
    }


def _create_bucket(ctx: Any, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _delete_policy_best_effort(logs, dest_name: str) -> None:
    try:
        logs.delete_delivery_destination_policy(deliveryDestinationName=dest_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""delivery-destination-policy-server-enforced-on-read."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delivery-destination-policy-server-enforced-on-read"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDeliveryDestinationPolicy on a destination succeeds with no policy content before
    PutDeliveryDestinationPolicy and after DeleteDeliveryDestinationPolicy, and returns the stored
    policy document exactly while it is set."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-deldest-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint of us-east-1 itself; the
        # literal below is that documented quirk, not a hardcoded region choice.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    bucket_arn = f"arn:aws:s3:::{bucket}"

    dest_name = ctx.unique_name("sim2real-behav-deliverydest-")
    logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="S3",
        deliveryDestinationConfiguration={"destinationResourceArn": bucket_arn},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    code_before, policy_before = _get_delivery_destination_policy(
        logs, dest_name
    )
    assert code_before is None and not policy_before, (
        f"expected a successful call with no policy content before any policy is assigned, got "
        f"code={code_before} policy={policy_before!r}"
    )

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowLogDeliveryActions",
                "Effect": "Allow",
                # A delivery destination's own resource policy (PutDeliveryDestinationPolicy)
                # is an IAM-style policy authorizing CreateDelivery against this account's
                # delivery resources -- it is not an S3 bucket policy for the delivery
                # service principal (that is configured separately, on the bucket itself).
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "logs:CreateDelivery",
                "Resource": [
                    f"arn:aws:logs:{ctx.region}:{account_id}:delivery-source:*",
                    f"arn:aws:logs:{ctx.region}:{account_id}:delivery:*",
                    f"arn:aws:logs:{ctx.region}:{account_id}:delivery-destination:*",
                ],
            }
        ],
    }
    logs.put_delivery_destination_policy(
        deliveryDestinationName=dest_name, deliveryDestinationPolicy=json.dumps(policy_doc)
    )

    fetched = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    stored_policy = json.loads(fetched["policy"]["deliveryDestinationPolicy"])
    assert stored_policy == policy_doc, (
        f"delivery destination policy did not round-trip: stored={stored_policy} "
        f"expected={policy_doc}"
    )

    logs.delete_delivery_destination_policy(deliveryDestinationName=dest_name)
    code_after, policy_after = _get_delivery_destination_policy(logs, dest_name)
    assert code_after is None and not policy_after, (
        f"expected a successful call with no policy content after "
        f"DeleteDeliveryDestinationPolicy, got code={code_after} policy={policy_after!r}"
    )


def _get_delivery_destination_policy(logs, dest_name: str):
    """Return (error_code, policy_document_string) of one GetDeliveryDestinationPolicy call."""
    from botocore.exceptions import ClientError

    try:
        resp = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    except ClientError as exc:
        return exc.response["Error"]["Code"], None
    return None, resp.get("policy", {}).get("deliveryDestinationPolicy")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

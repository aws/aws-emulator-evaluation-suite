"""op-contract-deleteResourcePolicy."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteResourcePolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy, DeleteResourcePolicy and PutResourcePolicy on a KeyValueStore ARN are each refused
    with InvalidArgument and their exact message (Put and Delete name the VPC origin requirement), and
    the store is unaffected: resource policies apply only to VPC origins."""
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-rp-kvs-")
    kvs = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    kvs_arn = kvs["KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_kvs(cf, name))

    # positive control: creation succeeded under the caller's account, so a rejection below
    # cannot be "everything is denied".
    expected_prefix = f"arn:aws:cloudfront::{account_id}:key-value-store/"
    assert kvs_arn.startswith(expected_prefix), (
        f"expected KeyValueStore ARN under {expected_prefix!r}, got {kvs_arn!r}"
    )

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "cloudfront:DescribeKeyValueStore",
                    "Resource": kvs_arn,
                }
            ],
        }
    )

    get_code, get_msg = _expect_invalid_argument(
        lambda: cf.get_resource_policy(ResourceArn=kvs_arn),
        "GetResourcePolicy",
    )
    assert get_code == "InvalidArgument", f"GetResourcePolicy: expected InvalidArgument, got {get_code}: {get_msg}"
    assert get_msg == "The ResourceArn parameter is required. Specify a valid ARN and try again.", (
        f"expected the exact refusal message, got {get_msg!r}"
    )

    delete_code, delete_msg = _expect_invalid_argument(
        lambda: cf.delete_resource_policy(ResourceArn=kvs_arn),
        "DeleteResourcePolicy",
    )
    assert delete_code == "InvalidArgument", (
        f"DeleteResourcePolicy: expected InvalidArgument, got {delete_code}: {delete_msg}"
    )
    assert delete_msg == "The specified resource type isn't valid. Specify a VPC origin and try again.", (
        f"expected the exact refusal message, got {delete_msg!r}"
    )

    put_code, put_msg = _expect_invalid_argument(
        lambda: cf.put_resource_policy(ResourceArn=kvs_arn, PolicyDocument=policy_doc),
        "PutResourcePolicy",
    )
    assert put_code == "InvalidArgument", f"PutResourcePolicy: expected InvalidArgument, got {put_code}: {put_msg}"
    assert put_msg == "The specified resource type isn't valid. Specify a VPC origin and try again.", (
        f"expected the exact refusal message, got {put_msg!r}"
    )

    # independent read, at a different operation than any of the three rejected calls: none
    # of them left a mark on the resource they were rejected against.
    still_there = cf.describe_key_value_store(Name=name)["KeyValueStore"]
    assert still_there["ARN"] == kvs_arn, (
        f"expected the KeyValueStore to be unaffected by the rejected calls, got ARN {still_there['ARN']!r}"
    )


def _expect_invalid_argument(fn, op_name: str):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error["Message"]
    else:
        raise AssertionError(f"{op_name}: expected a rejection, but the call succeeded: {result!r}")


def _safe_delete_kvs(cf, name: str) -> None:
    try:
        current = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""resource-policy-document-unicode-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-document-unicode-round-trip"
GROUP = "representation"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy document containing unicode characters and nested
    JSON structures round-trips through PutResourcePolicy/GetResourcePolicy
    with no re-serialization loss (no mangled unicode, no dropped nesting).
    """
    rs = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    namespace_arn = _create_namespace(ctx)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "UnicodeTest-h\u00e9llo-\u4e16\u754c-\U0001f680",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": namespace_arn,
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "aws:SourceArn": "arn:aws:s3:::\u00e9quipe-\u30c1\u30fc\u30e0-bucket",
                    }
                },
            }
        ],
    }
    rs.put_resource_policy(ResourceArn=namespace_arn, Policy=json.dumps(policy, ensure_ascii=False))
    ctx.on_cleanup(lambda: _delete_policy(rs, namespace_arn))

    got = rs.get_resource_policy(ResourceArn=namespace_arn)
    raw_stored = got["ResourcePolicy"]["Policy"]
    round_tripped = json.loads(raw_stored)

    assert round_tripped == policy, f"policy mutated on round-trip: {round_tripped!r} != {policy!r}"
    unicode_sid = "UnicodeTest-h\u00e9llo-\u4e16\u754c-\U0001f680"
    assert unicode_sid in raw_stored, (
        "unicode Sid not found verbatim in the raw stored policy string (possible "
        f"re-escaping to \\u sequences rather than raw UTF-8): expected substring="
        f"{unicode_sid!r} not in stored={raw_stored!r}"
    )


def _create_namespace(ctx: Any) -> str:
    rss = ctx.client("redshift-serverless")
    name = ctx.unique_name("sim2real-rpns-").lower().replace("_", "-")
    resp = rss.create_namespace(
        namespaceName=name, tags=[{"key": "sim2real", "value": "true"}]
    )
    ctx.on_cleanup(lambda: _delete_namespace(rss, name))
    _poll_until(
        probe=lambda: rss.get_namespace(namespaceName=name)["namespace"]["status"],
        predicate=lambda s: s == "AVAILABLE",
        timeout_s=60,
        interval_s=3,
    )
    return resp["namespace"]["namespaceArn"]


def _delete_namespace(rss: Any, name: str) -> None:
    try:
        rss.delete_namespace(namespaceName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_policy(rs: Any, resource_arn: str) -> None:
    try:
        rs.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

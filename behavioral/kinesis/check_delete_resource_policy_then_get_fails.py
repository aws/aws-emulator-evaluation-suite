"""delete-resource-policy-then-get-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-resource-policy-then-get-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteResourcePolicy, GetResourcePolicy no longer returns the deleted policy.

    It must raise ResourceNotFoundException or return a different (or empty) policy document."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-respol-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, name)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kinesis:DescribeStreamSummary",
                    "Resource": stream_arn,
                }
            ],
        }
    )
    kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=policy_doc)

    # Positive control: the policy we just set is retrievable right after being set.
    fetched = kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"]
    assert json.loads(fetched) == json.loads(policy_doc), (
        f"expected the just-set policy back verbatim, got {fetched!r}"
    )

    kinesis.delete_resource_policy(ResourceARN=stream_arn)

    # Revocation is normally visible on the first read; the bounded poll is a margin for
    # eventual consistency.
    deadline = time.monotonic() + 200.0
    outcome = None
    last_policy = fetched
    while time.monotonic() < deadline:
        try:
            resp = kinesis.get_resource_policy(ResourceARN=stream_arn)
        except ClientError as exc:
            outcome = ("error", exc.response["Error"]["Code"])
            break
        last_policy = resp.get("Policy")
        if not last_policy or json.loads(last_policy) != json.loads(policy_doc):
            outcome = ("changed", last_policy)
            break
        time.sleep(2)

    if outcome is None:
        raise AssertionError(
            "GetResourcePolicy kept returning the deleted policy verbatim for the whole "
            "200s poll window after DeleteResourcePolicy succeeded -- on a fresh real-AWS "
            "replay this resolves on the first poll, so this account/run diverges from that "
            "baseline and needs investigating rather than a raised budget"
        )

    kind, detail = outcome
    if kind == "error":
        assert detail == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after delete, got {detail!r}"
        )
    else:
        assert not detail or json.loads(detail) != json.loads(policy_doc), (
            f"expected the deleted policy to be gone or changed, still got it verbatim: {detail!r}"
        )


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


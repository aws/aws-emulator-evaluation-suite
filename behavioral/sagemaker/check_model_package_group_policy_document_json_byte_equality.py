"""model-package-group-policy-document-json-byte-equality."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "model-package-group-policy-document-json-byte-equality"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy's ResourcePolicy is returned value-exact (and, for the
    compact form we send, byte-identical) by GetModelPackageGroupPolicy -- no re-formatting,
    key reordering, or value coercion of the stored JSON blob."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-behav-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup():
        try:
            sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise
        sm.delete_model_package_group(ModelPackageGroupName=group_name)

    ctx.on_cleanup(_cleanup)

    group_arn = sm.describe_model_package_group(ModelPackageGroupName=group_name)[
        "ModelPackageGroupArn"
    ]

    # Unusual (but valid) value content: mixed case, punctuation, digits, nested arrays/dicts --
    # to make sure nothing gets coerced or truncated, not just whitespace preserved. ASCII-only:
    # PutModelPackageGroupPolicy rejects a non-ASCII
    # ResourcePolicy outright with ValidationException ("Policy string can only contain ASCII
    # characters"), so fidelity here is probed via formatting/value content, not unicode. Sid
    # is alphanumeric-only: a Sid with punctuation is
    # rejected with ValidationException ("The following Statement Ids are invalid"), so the
    # unusual punctuation/casing content lives in a Condition value instead.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealOddCasingMarker123",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sagemaker:DescribeModelPackage", "sagemaker:ListModelPackages"],
                "Resource": group_arn,
                "Condition": {
                    "StringEquals": {"aws:ResourceTag/sim2realLabel": "Odd_Casing-123_Marker!"}
                },
            }
        ],
    }
    # Compact separators -- the exact bytes we send.
    policy_json = json.dumps(policy, separators=(",", ":"), ensure_ascii=False)

    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=policy_json
    )

    resp = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    returned = resp["ResourcePolicy"]

    # Value-exact: parsing both sides must yield identical structures (order-insensitive at
    # the dict level, but no value may be dropped, coerced, or mangled).
    assert json.loads(returned) == policy, "policy document value mismatch after round-trip"

    # Byte-identical for the exact compact string we sent (SageMaker stores the blob as-is).
    assert returned == policy_json, (
        f"ResourcePolicy was not returned byte-identical: sent={policy_json!r} got={returned!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

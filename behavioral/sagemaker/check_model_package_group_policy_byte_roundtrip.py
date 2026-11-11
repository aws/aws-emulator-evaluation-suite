"""model-package-group-policy-byte-roundtrip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-policy-byte-roundtrip"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ASCII resource policy (scalar Action, single-key Condition) put on a model package
    group reads back byte-identical, while a non-ASCII policy is rejected ValidationException
    and leaves the stored policy unchanged."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": "model-package-group-policy-byte-roundtrip"}],
    )["ModelPackageGroupArn"]

    def _cleanup_group() -> None:
        try:
            sm.delete_model_package_group(ModelPackageGroupName=group_name)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationException" and "does not exist" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup_group)

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribeWithCondition",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": group_arn,
                "Condition": {
                    "StringEquals": {"aws:ResourceTag/team": "Team_Alpha-Ops.42"}
                },
            }
        ],
    }
    # Explicit, deterministic serialization: no extra whitespace normalization to hide
    # behind.
    policy_str = json.dumps(policy_doc, separators=(",", ":"))

    sm.put_model_package_group_policy(ModelPackageGroupName=group_name, ResourcePolicy=policy_str)

    def _cleanup_policy() -> None:
        try:
            sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise

    ctx.on_cleanup(_cleanup_policy)

    got = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    assert got == policy_str, (got, policy_str)
    # And it must still be valid, semantically-identical JSON.
    assert json.loads(got) == policy_doc, (json.loads(got), policy_doc)

    # Positive control above proves the group/call shape is healthy, so this is a
    # specific ASCII-only validation rule, not a blanket rejection of every Put.
    non_ascii_doc = dict(policy_doc)
    non_ascii_doc["Statement"] = [
        dict(policy_doc["Statement"][0], Sid="café-日本語-🚀")
    ]
    non_ascii_str = json.dumps(non_ascii_doc, ensure_ascii=False, separators=(",", ":"))
    try:
        sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=non_ascii_str
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "ValidationException", (code, message)
        expected_message = "Invalid Policy: Policy string can only contain ASCII characters"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(
            "expected PutModelPackageGroupPolicy to reject a non-ASCII ResourcePolicy"
        )

    # The rejected write must not have clobbered the earlier ASCII policy.
    still_there = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)[
        "ResourcePolicy"
    ]
    assert still_there == policy_str, (still_there, policy_str)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

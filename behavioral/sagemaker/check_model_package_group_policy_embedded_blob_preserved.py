"""model-package-group-policy-embedded-blob-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "model-package-group-policy-embedded-blob-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy with a base64 blob in an IAM condition value, written by PutModelPackageGroupPolicy,
    comes back from GetModelPackageGroupPolicy with the blob unaltered and the statement intact."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}]

    group_name = ctx.unique_name("sim2real-mppolicy-")
    create_resp = sm.create_model_package_group(
        ModelPackageGroupName=group_name, Tags=resource_tags
    )
    group_arn = create_resp["ModelPackageGroupArn"]

    def _cleanup_group():
        sm.delete_model_package_group(ModelPackageGroupName=group_name)

    ctx.on_cleanup(_cleanup_group)
    # CreateModelPackageGroup auto-creates a SageMaker Lineage "Context" tracking entity
    # for the group; DeleteModelPackageGroup does NOT cascade-delete it.
    ctx.on_cleanup(lambda: _delete_lineage_context(sm, group_arn))

    # A base64 blob (using the standard alphabet, including '+' and '/') embedded
    # as an arbitrary IAM condition value -- syntactically valid JSON/IAM policy,
    # but the value itself is opaque binary-derived data.
    import base64

    blob = base64.b64encode(b"\x00\x01\x02\xffsim2real-binary-payload\xfe\xfd" * 3).decode("ascii")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribeFromSelf",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackage",
                "Resource": group_arn,
                "Condition": {"StringEquals": {"sagemaker:ResourceTag/blob": blob}},
            }
        ],
    }
    resource_policy_str = json.dumps(policy)

    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=resource_policy_str
    )
    ctx.on_cleanup(
        lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
    )

    got = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    got_policy = json.loads(got["ResourcePolicy"])
    got_blob = got_policy["Statement"][0]["Condition"]["StringEquals"][
        "sagemaker:ResourceTag/blob"
    ]
    assert got_blob == blob, (
        f"embedded base64 blob not byte-identical: wrote {blob!r}, read back {got_blob!r}"
    )
    # The full statement structure (not just the blob) must also survive intact.
    got_resource = got_policy["Statement"][0]["Resource"]
    assert got_resource == group_arn, (
        f"statement Resource not preserved: expected {group_arn!r}, got {got_resource!r}"
    )
    got_sid = got_policy["Statement"][0]["Sid"]
    assert got_sid == "AllowDescribeFromSelf", (
        f"statement Sid not preserved: expected 'AllowDescribeFromSelf', got {got_sid!r}"
    )


def _delete_lineage_context(sm, group_arn: str) -> None:
    for summary in sm.list_contexts(SourceUri=group_arn).get("ContextSummaries", []):
        try:
            sm.delete_context(ContextName=summary["ContextName"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

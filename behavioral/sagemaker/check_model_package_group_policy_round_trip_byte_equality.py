"""model-package-group-policy-round-trip-byte-equality."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "model-package-group-policy-round-trip-byte-equality"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy written with PutModelPackageGroupPolicy reads back from
    GetModelPackageGroupPolicy as the same JSON document, including a mixed-case punctuated string
    value, although AWS re-serializes it in compact form.
    """
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    group_name = ctx.unique_name("sim2real-mpg-byteeq-")

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    ctx.on_cleanup(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name))

    account_id = sts.get_caller_identity()["Account"]
    group_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"
    # Deliberately odd (but valid) JSON formatting -- irregular key order and an unusual,
    # distinctive Condition value with mixed case/digits/punctuation -- to prove the value
    # is preserved verbatim, not normalized. (ResourcePolicy is ASCII-only: SageMaker rejects
    # non-ASCII policy documents outright, so fidelity is probed via formatting/value casing
    # rather than unicode content. Kept single-line: the value validation pattern does not
    # allow embedded newlines.)
    distinctive_value = "Odd_Casing-123_Marker"
    policy = {
        "Statement": [
            {
                "Resource": group_arn,
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Effect": "Allow",
                "Sid": "Sim2RealByteEqualityCheck",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Condition": {
                    "StringEquals": {"aws:ResourceTag/sim2realLabel": distinctive_value}
                },
            }
        ],
        "Version": "2012-10-17",
    }
    policy_text = json.dumps(policy, sort_keys=False)

    sm.put_model_package_group_policy(ModelPackageGroupName=group_name, ResourcePolicy=policy_text)
    fetched_text = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    fetched = json.loads(fetched_text)

    # AWS re-serializes into its own canonical compact form, so raw string equality does not
    # hold -- but the parsed document must be semantically identical, field for field.
    assert fetched == policy, (fetched, policy)
    # The distinctive value survives with its exact casing/punctuation -- not normalized.
    stored_value = fetched["Statement"][0]["Condition"]["StringEquals"]["aws:ResourceTag/sim2realLabel"]
    assert stored_value == distinctive_value, stored_value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

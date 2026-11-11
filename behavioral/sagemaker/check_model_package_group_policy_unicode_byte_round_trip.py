"""model-package-group-policy-unicode-byte-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-policy-unicode-byte-round-trip"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags(
    "axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control"
)
def run(ctx) -> None:
    """PutModelPackageGroupPolicy refuses a policy containing non-ASCII characters with
    ValidationException "Invalid Policy: Policy string can only contain ASCII characters", and the
    ASCII policy put beforehand stays in place unchanged.
    """
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-sm-mpg-uni-")
    group_arn = sm.create_model_package_group(ModelPackageGroupName=group_name)[
        "ModelPackageGroupArn"
    ]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    def _policy(sid: str) -> dict:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sagemaker:DescribeModelPackage",
                    "Resource": group_arn,
                }
            ],
        }

    # Positive control: an ASCII policy stores and round-trips byte-for-byte, and proves
    # the account/credentials/plumbing are healthy before trusting the negative below.
    control_policy = _policy("AsciiControlSid")
    control_json = json.dumps(control_policy)
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=control_json
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name))
    stored_control = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)[
        "ResourcePolicy"
    ]
    assert json.loads(stored_control) == control_policy, (
        f"positive control failed: {stored_control!r} != {control_json!r}"
    )

    # Break exactly one thing: the same policy shape, but with a unicode/emoji Sid, sent
    # with the raw non-ASCII bytes on the wire -- ensure_ascii=False, because an escaped
    # \u-form would still be pure ASCII and would not exercise the rule.
    unicode_sid = "\u00e9quipe-\U0001f680-\u4e2d\u6587-Sid"
    unicode_json = json.dumps(_policy(unicode_sid), ensure_ascii=False)

    try:
        sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=unicode_json
        )
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err}"
        assert err["Message"] == "Invalid Policy: Policy string can only contain ASCII characters", err
    else:
        raise AssertionError(
            "PutModelPackageGroupPolicy accepted a non-ASCII policy document; real AWS "
            "rejects this with ValidationException (policy strings must be ASCII-only)"
        )

    # Effect absent: the rejected call must not have replaced the control policy.
    stored_after = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)[
        "ResourcePolicy"
    ]
    assert json.loads(stored_after) == control_policy, (
        f"rejected non-ASCII PutModelPackageGroupPolicy still took effect: {stored_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

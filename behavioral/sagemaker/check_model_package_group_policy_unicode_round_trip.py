"""model-package-group-policy-unicode-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-policy-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy rejects a non-ASCII policy (CJK, emoji, accents) with
    ValidationException, because SageMaker limits ResourcePolicy to ASCII; an ASCII policy on the
    same group applies (positive control) and survives the rejected write."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-mpg-uni-")

    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _delete_group(sm, group_name))

    ascii_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribeModelPackageGroup",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "sagemaker:DescribeModelPackageGroup",
                    "sagemaker:ListModelPackages",
                ],
                "Resource": group_arn,
            }
        ],
    }
    ascii_str = json.dumps(ascii_policy)

    sm.put_model_package_group_policy(ModelPackageGroupName=group_name, ResourcePolicy=ascii_str)
    ctx.on_cleanup(lambda: _delete_policy_quiet(sm, group_name))

    # AWS re-serializes the stored policy into its own canonical compact form (no
    # incidental whitespace), so the byte string is not preserved verbatim -- but the
    # parsed document must still be value-identical.
    got_ascii_parsed = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert got_ascii_parsed == ascii_policy, (
        f"positive control failed: ASCII-only policy not value-identical after round trip: "
        f"got {got_ascii_parsed!r}, expected {ascii_policy!r}"
    )

    unicode_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "允许访问-🚀-Ünïçødé-team",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "sagemaker:DescribeModelPackageGroup",
                    "sagemaker:ListModelPackages",
                ],
                "Resource": group_arn,
                "Condition": {
                    "StringEquals": {"aws:PrincipalTag/团队": "数据科学-ml-🧪"}
                },
            }
        ],
    }
    # ensure_ascii=False so the wire body itself carries the raw unicode bytes -- this is
    # the exact payload real AWS rejects, not an escaped stand-in for it.
    unicode_str = json.dumps(unicode_policy, ensure_ascii=False)

    code, message = _put_error(sm, group_name, unicode_str)
    assert code == "ValidationException", (
        f"expected ValidationException for a non-ASCII ResourcePolicy, got {code!r} ({message!r})"
    )
    assert message == "Invalid Policy: Policy string can only contain ASCII characters", message

    # Effect-absent: the rejected PUT must not have replaced or removed the ASCII policy
    # the positive control put in place.
    still_ascii_parsed = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert still_ascii_parsed == ascii_policy, (
        f"rejected unicode PUT altered the stored policy: got {still_ascii_parsed!r}, "
        f"expected unchanged {ascii_policy!r}"
    )


def _put_error(sm, group_name: str, resource_policy: str):
    try:
        sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=resource_policy
        )
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected PutModelPackageGroupPolicy to raise for a non-ASCII policy, but it succeeded")


def _delete_group(sm, name: str) -> None:
    _delete_if_present(lambda: sm.delete_model_package_group(ModelPackageGroupName=name))


_GONE_MARKERS = ("does not exist", "not found", "cannot find")


def _delete_if_present(fn) -> None:
    """Teardown delete: returns when SageMaker reports the resource is already gone and
    raises any other failure."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        message = err.get("Message", "").lower()
        gone = err["Code"] == "ResourceNotFound" or (
            err["Code"] == "ValidationException" and any(m in message for m in _GONE_MARKERS)
        )
        if not gone:
            raise


def _delete_policy_quiet(sm, name: str) -> None:
    try:
        sm.delete_model_package_group_policy(ModelPackageGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

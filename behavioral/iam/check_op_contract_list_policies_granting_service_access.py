"""op-contract-list-policies-granting-service-access."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-policies-granting-service-access"
GROUP = "error-semantics"
SERVICES = ["iam"]

_S3_READ_ONLY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPoliciesGrantingServiceAccess reports the policy that grants s3 access to a
    user; a nonexistent principal ARN -> NoSuchEntityException."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    user_name = ctx.unique_name("sim2real-behav-user-")
    user_arn = iam.create_user(
        UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.attach_user_policy(UserName=user_name, PolicyArn=_S3_READ_ONLY_ARN)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=_S3_READ_ONLY_ARN))

    resp = iam.list_policies_granting_service_access(
        Arn=user_arn, ServiceNamespaces=["s3"]
    )
    entries = resp["PoliciesGrantingServiceAccess"]
    s3_entry = next((e for e in entries if e["ServiceNamespace"] == "s3"), None)
    assert s3_entry is not None, f"no s3 entry in PoliciesGrantingServiceAccess: {entries}"
    policy_names = [p["PolicyName"] for p in s3_entry["Policies"]]
    assert "AmazonS3ReadOnlyAccess" in policy_names, (
        f"expected AmazonS3ReadOnlyAccess among granting policies, got {policy_names}"
    )

    bogus_arn = f"arn:aws:iam::{account_id}:user/{ctx.unique_name('sim2real-nope-')}"
    code, message = _error(
        lambda: iam.list_policies_granting_service_access(
            Arn=bogus_arn, ServiceNamespaces=["s3"]
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"ARN {bogus_arn} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""op-contract-describe-identity-id-format."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-identity-id-format"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityIdFormat for the caller's ARN returns one instance status with a boolean UseLongIds
    and lists instance unscoped; a non-ARN principal fails with InvalidTargetArn.Unknown and its exact
    message."""
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]

    scoped = ec2.describe_identity_id_format(PrincipalArn=caller_arn, Resource="instance")["Statuses"]
    assert len(scoped) == 1, f"expected exactly one status entry for 'instance', got {scoped}"
    assert scoped[0]["Resource"] == "instance", f"expected Resource 'instance', got {scoped[0]}"
    assert isinstance(scoped[0]["UseLongIds"], bool), f"expected UseLongIds to be a bool, got {scoped[0]!r}"

    unscoped = ec2.describe_identity_id_format(PrincipalArn=caller_arn)["Statuses"]
    resources = {item["Resource"] for item in unscoped}
    assert "instance" in resources, f"expected 'instance' in the resource-type set, got {resources}"

    # Error boundary: a malformed principal ARN is rejected server-side.
    code, message = _error(
        lambda: ec2.describe_identity_id_format(PrincipalArn="sim2real-not-an-arn", Resource="instance")
    )
    assert code == "InvalidTargetArn.Unknown", f"expected InvalidTargetArn.Unknown, got {code}"
    assert message == "Invalid TargetArn: sim2real-not-an-arn", message


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""publisher-registration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publisher-registration-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterPublisher from an account not enrolled as an AWS Marketplace seller (a console-only
    step) fails CFNRegistryException naming that gate, and DescribePublisher shows no record.
    """
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: an unrelated, always-available read must succeed, so a
    # refusal below cannot be mistaken for "everything is denied".
    cfn.describe_account_limits()

    try:
        cfn.register_publisher(AcceptTermsAndConditions=True)
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "CFNRegistryException", (
            f"expected CFNRegistryException, got {error['Code']}: {error['Message']}"
        )
        expected = "You must be a valid AWS Marketplace Seller to be registered as a publisher"
        assert error["Message"] == expected, (
            f"expected the Marketplace Seller entitlement refusal {expected!r}, got: {error['Message']!r}"
        )
    else:
        raise AssertionError(
            "RegisterPublisher succeeded -- this sandbox account is enrolled as "
            "an AWS Marketplace seller, so the withdrawal this check asserts no "
            "longer holds and the happy-path lifecycle needs to be exercised "
            "instead"
        )

    try:
        cfn.describe_publisher()
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "CFNRegistryException", (
            f"expected CFNRegistryException, got {error['Code']}: {error['Message']}"
        )
        expected = (
            f"The account [{account}] is not registered as a publisher, if you want to describe "
            "a specific publisher, please specify the publisherID"
        )
        assert error["Message"] == expected, (
            f"expected confirmation that no publisher record exists {expected!r}, got: {error['Message']!r}"
        )
    else:
        raise AssertionError(
            "DescribePublisher succeeded after RegisterPublisher was refused -- "
            "the account is registered as a publisher despite the refusal above"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

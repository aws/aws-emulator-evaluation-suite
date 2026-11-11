"""publisher-and-type-testing-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publisher-and-type-testing-lifecycle"
GROUP = 'registry'
SERVICES = ['cloudformation']


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _publisher_registered(cf) -> bool:
    """True when DescribePublisher returns a publisher; False when it refuses with
    CFNRegistryException (no publisher is registered for this account)."""
    try:
        cf.describe_publisher()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "CFNRegistryException":
            return False
        raise
    return True


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Publisher registration gates PublishType; TestType gates readiness for publishing."""
    cf = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]

    already_registered = _publisher_registered(cf)

    if already_registered:
        # Re-registering an already-registered account is tolerated -- there is no
        # DeregisterPublisher API to undo the first registration, so a re-run against a
        # dirty account must not treat this as an error.
        cf.register_publisher(AcceptTermsAndConditions=True)
        pub = cf.describe_publisher()
        # DescribePublisher documents every registered publisher as VERIFIED.
        assert pub.get("PublisherStatus") == "VERIFIED", pub
    else:
        # A fresh, non-Marketplace-seller account: RegisterPublisher is rejected at the same
        # registry gate as the DescribePublisher probe above.
        reg_code, reg_message = _error(lambda: cf.register_publisher(AcceptTermsAndConditions=True))
        assert reg_code == "CFNRegistryException", (
            f"expected RegisterPublisher on a non-Marketplace-seller account to be rejected "
            f"with CFNRegistryException, got {reg_code!r}"
        )
        expected = "You must be a valid AWS Marketplace Seller to be registered as a publisher"
        assert reg_message == expected, f"expected message {expected!r}, got {reg_message!r}"
        # Effect-absent: the rejected RegisterPublisher must not have taken effect -- an
        # independent read still reports no publisher.
        after_code, after_message = _error(lambda: cf.describe_publisher())
        assert after_code == "CFNRegistryException", (
            f"expected DescribePublisher to still report no publisher after a rejected "
            f"RegisterPublisher, got {after_code!r}"
        )
        expected = (
            f"The account [{account}] is not registered as a publisher, if you want to describe "
            "a specific publisher, please specify the publisherID"
        )
        assert after_message == expected, f"expected message {expected!r}, got {after_message!r}"

    bogus_arn = (
        f"arn:aws:cloudformation:{ctx.region}:{account}:type/resource/"
        f"Sim2realBehav-Nope-Nope/00000001"
    )

    # TestType against a type that was never registered: real CloudFormation rejects
    # this at the publisher gate, before any "has it passed contract tests" business
    # logic applies.
    test_code, test_message = _error(lambda: cf.test_type(Arn=bogus_arn))
    assert test_code == "CFNRegistryException", (
        f"expected TestType on a nonexistent type to be rejected with CFNRegistryException, "
        f"got {test_code!r}"
    )
    expected = "You must register as a publisher with CloudFormation to call test-type."
    assert test_message == expected, f"expected message {expected!r}, got {test_message!r}"

    # PublishType before a type has ever reached TestType-PASSED: the versioned ARN is
    # refused before any registry lookup, since only a type's default version is publishable.
    publish_code, publish_message = _error(lambda: cf.publish_type(Arn=bogus_arn))
    assert publish_code == "CFNRegistryException", (
        f"expected PublishType on a nonexistent/untested type to be rejected with "
        f"CFNRegistryException, got {publish_code!r}"
    )
    expected = "Only default version can be published. Please remove versionId from Arn"
    assert publish_message == expected, f"expected message {expected!r}, got {publish_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

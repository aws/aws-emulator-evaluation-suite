"""type-not-found-across-apis-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-not-found-across-apis-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unregistered extension name returns TypeNotFoundException across type-management APIs.

    ActivateType, TestType and PublishType refuse earlier with CFNRegistryException.
    """
    cfn = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: DescribeType discriminates a real type from a fake one.
    control = cfn.describe_type(Type="RESOURCE", TypeName="AWS::SNS::Topic")
    assert control["TypeName"] == "AWS::SNS::Topic" and control["Visibility"] == "PUBLIC", (
        f"positive control: DescribeType(AWS::SNS::Topic) returned "
        f"TypeName={control.get('TypeName')!r} Visibility={control.get('Visibility')!r}"
    )

    # TypeName must match [A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64}::[A-Za-z0-9]{2,64} -- no
    # hyphens allowed, so build it from hex instead of ctx.unique_name().
    type_name = f"SimParity::Fidelity::NoSuch{uuid.uuid4().hex[:12]}"
    # PublicTypeArn pattern: arn:...::type/<category>/<publisherId>/<typename-with-dashes>/<version>
    # -- publisherId must be a real-looking (12-40 alnum) id and the type-name segment
    # uses dashes, not "::"; a malformed ARN here trips ValidationError before the
    # not-found check ever runs.
    publisher_id = uuid.uuid4().hex
    dashed_type_name = type_name.replace("::", "-")
    public_arn = (
        f"arn:aws:cloudformation:{ctx.region}::type/resource/{publisher_id}/"
        f"{dashed_type_name}/00000001"
    )

    strict_checks = [
        ("DeactivateType", lambda: cfn.deactivate_type(TypeName=type_name, Type="RESOURCE")),
        ("DeregisterType", lambda: cfn.deregister_type(TypeName=type_name, Type="RESOURCE")),
        (
            "SetTypeConfiguration",
            lambda: cfn.set_type_configuration(TypeName=type_name, Type="RESOURCE", Configuration="{}"),
        ),
        (
            "SetTypeDefaultVersion",
            lambda: cfn.set_type_default_version(TypeName=type_name, Type="RESOURCE", VersionId="00000001"),
        ),
        ("DescribeType", lambda: cfn.describe_type(TypeName=type_name, Type="RESOURCE")),
    ]
    expected_not_found = ("TypeNotFoundException", f"The type '{type_name}' cannot be found.")
    for label, fn in strict_checks:
        error = _error(fn)
        assert error == expected_not_found, f"{label} returned {error!r}, expected {expected_not_found!r}"

    # ActivateType validates the PublicTypeArn before any registry lookup: a public ARN
    # that carries a version segment is refused with CFNRegistryException, not
    # TypeNotFoundException.
    activate_error = _error(lambda: cfn.activate_type(Type="RESOURCE", PublicTypeArn=public_arn))
    expected_activate = ("CFNRegistryException", "You cannot specify public version number in the arn")
    assert activate_error == expected_activate, (
        f"ActivateType returned {activate_error!r}, expected {expected_activate!r}"
    )

    # TestType requires the caller to be a registered extension publisher, and refuses an
    # account that is not one with CFNRegistryException before resolving the type.
    test_error = _error(lambda: cfn.test_type(TypeName=type_name, Type="RESOURCE"))
    expected_test = (
        "CFNRegistryException",
        "You must register as a publisher with CloudFormation to call test-type.",
    )
    assert test_error == expected_test, f"TestType returned {test_error!r}, expected {expected_test!r}"

    # PublishType also refuses a non-publisher account before resolving the type.
    publish_error = _error(lambda: cfn.publish_type(TypeName=type_name, Type="RESOURCE"))
    expected_publish = (
        "CFNRegistryException",
        f"The account {account_id} is not verified as a publisher. Please register as publisher first",
    )
    assert publish_error == expected_publish, (
        f"PublishType returned {publish_error!r}, expected {expected_publish!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

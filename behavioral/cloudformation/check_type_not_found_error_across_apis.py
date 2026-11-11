"""type-not-found-error-across-apis."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-not-found-error-across-apis"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unregistered extension name/arn returns TypeNotFoundException consistently
    across every type-management API that accepts a type identifier."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    # Positive control: DescribeType against AWS's own always-registered public type
    # proves the type-management surface (endpoint, region, credentials) is otherwise
    # healthy, so the TypeNotFoundException asserted below is a fact about the
    # unregistered identifier -- not indistinguishable from "this API rejects every
    # call regardless of input".
    control = cfn.describe_type(Type="RESOURCE", TypeName="AWS::SNS::Topic")
    assert control["TypeName"] == "AWS::SNS::Topic", control["TypeName"]
    assert control["Visibility"] == "PUBLIC", control["Visibility"]

    type_name = "Sim2RealTest::NoSuchResource::Type"
    private_arn = (
        f"arn:aws:cloudformation:{region}:{account}:type/resource/"
        "Sim2RealTest-NoSuchResource-Type/00000001"
    )
    # PublicTypeArn pattern: arn:...::type/<category>/<publisherId>/<typename-with-dashes>/<version>
    # -- publisherId is a real-looking (12-40 alnum) id, distinct from the type-name
    # segment; a malformed ARN here trips ValidationError before the not-found check
    # ever runs.
    public_arn = (
        f"arn:aws:cloudformation:{region}::type/resource/"
        f"{'b' * 20}/Sim2RealBogusPublisher-NoSuchResource-Type/00000001"
    )

    checks = [
        ("DescribeType", lambda: cfn.describe_type(Type="RESOURCE", TypeName=type_name)),
        ("DeregisterType", lambda: cfn.deregister_type(Type="RESOURCE", TypeName=type_name)),
        (
            "SetTypeDefaultVersion",
            lambda: cfn.set_type_default_version(
                Type="RESOURCE", TypeName=type_name, VersionId="00000001"
            ),
        ),
        ("DeactivateType", lambda: cfn.deactivate_type(Type="RESOURCE", TypeName=type_name)),
        (
            "SetTypeConfiguration",
            lambda: cfn.set_type_configuration(
                TypeName=type_name, Type="RESOURCE", Configuration=json.dumps({"a": 1})
            ),
        ),
    ]
    expected_not_found = ("TypeNotFoundException", f"The type '{type_name}' cannot be found.")
    for label, fn in checks:
        error = _error(fn)
        assert error == expected_not_found, (
            f"{label} against an unregistered type identifier: expected "
            f"{expected_not_found!r}, got {error!r}"
        )

    # PublishType validates the ARN before resolving it: a private ARN carrying a version
    # segment is refused with CFNRegistryException rather than the plain
    # TypeNotFoundException used by the describe/deregister/set-default-version/deactivate
    # family.
    publish_error = _error(lambda: cfn.publish_type(Arn=private_arn))
    expected_publish = (
        "CFNRegistryException",
        "Only default version can be published. Please remove versionId from Arn",
    )
    assert publish_error == expected_publish, (
        f"PublishType against an unregistered type identifier: expected "
        f"{expected_publish!r}, got {publish_error!r}"
    )

    # ActivateType validates the PublicTypeArn before any registry lookup: a public ARN
    # carrying a version segment is refused with CFNRegistryException.
    activate_error = _error(lambda: cfn.activate_type(PublicTypeArn=public_arn))
    expected_activate = ("CFNRegistryException", "You cannot specify public version number in the arn")
    assert activate_error == expected_activate, (
        f"ActivateType against an unregistered public type: expected "
        f"{expected_activate!r}, got {activate_error!r}"
    )

    # TestType requires the caller to be a registered extension publisher, and refuses an
    # account that is not one with CFNRegistryException before resolving the type.
    test_error = _error(lambda: cfn.test_type(Type="RESOURCE", TypeName=type_name))
    expected_test = (
        "CFNRegistryException",
        "You must register as a publisher with CloudFormation to call test-type.",
    )
    assert test_error == expected_test, (
        f"TestType against an unregistered type identifier: expected "
        f"{expected_test!r}, got {test_error!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

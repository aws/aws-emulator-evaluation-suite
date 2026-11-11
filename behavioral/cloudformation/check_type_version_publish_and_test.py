"""type-version-publish-and-test."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "type-version-publish-and-test"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestType/PublishType reject a never-registered type version ARN with CFNRegistryException.

    DescribeType confirms the same ARN is unresolvable, and a real AWS-owned type is the control.
    """
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")

    aws_owned_type_name = "AWS::SNS::Topic"
    described = cfn.describe_type(Type="RESOURCE", TypeName=aws_owned_type_name)
    assert described["TypeName"] == aws_owned_type_name, (
        f"expected DescribeType to answer for {aws_owned_type_name!r} (positive control "
        f"that the registry API is reachable), got TypeName={described.get('TypeName')!r}"
    )

    account_id = sts.get_caller_identity()["Account"]
    fake_type_arn = (
        f"arn:aws:cloudformation:{ctx.region}:{account_id}:"
        "type/resource/Sim2Real-Probe-Nonexistent/00000001"
    )

    test_error = _error(lambda: cfn.test_type(Arn=fake_type_arn))
    expected_test = (
        "CFNRegistryException",
        "You must register as a publisher with CloudFormation to call test-type.",
    )
    assert test_error == expected_test, (
        f"expected {expected_test!r} from TestType on a nonexistent type version, got {test_error!r}"
    )

    publish_error = _error(lambda: cfn.publish_type(Arn=fake_type_arn))
    expected_publish = (
        "CFNRegistryException",
        "Only default version can be published. Please remove versionId from Arn",
    )
    assert publish_error == expected_publish, (
        f"expected {expected_publish!r} from PublishType on a nonexistent type version, got {publish_error!r}"
    )

    describe_error = _error(lambda: cfn.describe_type(Arn=fake_type_arn))
    expected_describe = ("TypeNotFoundException", "The type 'Sim2Real::Probe::Nonexistent' cannot be found.")
    assert describe_error == expected_describe, (
        f"expected {expected_describe!r} from DescribeType on the same nonexistent type "
        f"version ARN, got {describe_error!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

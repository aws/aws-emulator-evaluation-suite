"""type-registry-not-found-errors."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-registry-not-found-errors"
GROUP = 'errors'
SERVICES = ['cloudformation']


def _expect_error(fn, expected):
    """Assert fn() raises a ClientError whose (Error.Code, Error.Message) is exactly *expected*;
    an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
        assert error == expected, f"expected {expected!r}, got {error!r}"
        return error
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Unknown extension-type identifiers raise TypeNotFoundException, and
    malformed/nonexistent registry requests raise CFNRegistryException,
    consistently across every type-management operation."""
    cf = ctx.client("cloudformation")
    token = ctx.unique_name("")[:20]
    missing_type = f"Sim2realBehav::Probe::{token}"
    private_arn = (
        f"arn:aws:cloudformation:{ctx.region}:111122223333:type/resource/"
        f"{missing_type.replace('::', '-')}/00000001"
    )
    public_arn = (
        f"arn:aws:cloudformation:{ctx.region}::type/resource/"
        f"{missing_type.replace('::', '-')}/00000001"
    )

    # Positive control: an AWS-native resource type needs no registration and is
    # describable in every account/region, so this proves DescribeType (and this
    # account's credentials/wiring for the type-management API family) works
    # normally. Without it, a target that always answers TypeNotFoundException --
    # including for real, existing types -- would pass every assertion below.
    real = cf.describe_type(Type="RESOURCE", TypeName="AWS::S3::Bucket")
    assert real.get("TypeName") == "AWS::S3::Bucket", (
        f"positive control: expected DescribeType(AWS::S3::Bucket) to resolve the "
        f"real type, got TypeName={real.get('TypeName')!r}"
    )

    not_found = f"The type '{missing_type}' cannot be found."
    _expect_error(
        lambda: cf.describe_type(Type="RESOURCE", TypeName=missing_type),
        ("TypeNotFoundException", not_found),
    )
    _expect_error(
        lambda: cf.activate_type(PublicTypeArn=public_arn),
        ("CFNRegistryException", "TypeName is invalid"),
    )
    _expect_error(
        lambda: cf.deactivate_type(Type="RESOURCE", TypeName=missing_type),
        ("TypeNotFoundException", not_found),
    )
    _expect_error(
        lambda: cf.deregister_type(Type="RESOURCE", TypeName=missing_type),
        ("TypeNotFoundException", not_found),
    )
    _expect_error(
        lambda: cf.publish_type(Arn=private_arn),
        ("CFNRegistryException", "Type not found in your account."),
    )
    _expect_error(
        lambda: cf.test_type(Arn=private_arn),
        ("TypeNotFoundException", not_found),
    )
    _expect_error(
        lambda: cf.set_type_configuration(
            TypeName=missing_type, Type="RESOURCE", Configuration='{"Properties":{}}'
        ),
        ("TypeNotFoundException", not_found),
    )
    _expect_error(
        lambda: cf.set_type_default_version(
            Type="RESOURCE", TypeName=missing_type, VersionId="00000001"
        ),
        ("TypeNotFoundException", not_found),
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

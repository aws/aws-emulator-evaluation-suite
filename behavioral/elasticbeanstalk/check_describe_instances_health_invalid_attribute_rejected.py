"""describe-instances-health-invalid-attribute-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-instances-health-invalid-attribute-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstancesHealth with an unmodeled AttributeName fails with ValidationError and the exact message, while
    a modeled AttributeName on the same unknown environment fails with InvalidParameterValue instead."""
    eb = ctx.client("elasticbeanstalk")
    env_name = ctx.unique_name("sim2real-ebih-env-")

    control_code, control_message = _error_code(lambda: eb.describe_instances_health(
        EnvironmentName=env_name,
        AttributeNames=["HealthStatus"],
    ))
    assert control_code == "InvalidParameterValue", (
        f"positive control (modeled attribute, fake env): expected InvalidParameterValue, "
        f"got {control_code}"
    )
    control_expected = f"No Environment found for EnvironmentName = '{env_name}'."
    assert control_message == control_expected, (
        f"positive control (modeled attribute, fake env): expected {control_expected!r}, "
        f"got {control_message!r}"
    )

    code, message = _error_code(lambda: eb.describe_instances_health(
        EnvironmentName=env_name,
        AttributeNames=["NotARealAttribute"],
    ))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = (
        "1 validation error detected: Value '[NotARealAttribute]' at 'attributeNames' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
        "[All, Color, Deployment, LaunchedAt, AvailabilityZone, Causes, RefreshedAt, HealthStatus, "
        "InstanceType, System, ApplicationMetrics]]"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # (b)/(c): the invalid call left no lasting effect -- the API remains functional immediately
    # afterward for an ordinary, unrelated call.
    resp = eb.describe_applications()
    assert "Applications" in resp, f"expected an Applications key in the response, got {resp!r}"


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

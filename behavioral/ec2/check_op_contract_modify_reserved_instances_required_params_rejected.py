"""op-contract-modify-reserved-instances-required-params-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-reserved-instances-required-params-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyReservedInstances sent without TargetConfigurations (past client-side validation) fails with
    MissingParameter, and a valid configuration for an unknown Reserved Instance id fails with
    InvalidInput; both exact messages are asserted and the two codes differ."""
    ec2 = ctx.client("ec2")
    zone = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    ec2_unvalidated = _no_validate_client(ctx, "ec2")

    # server-side contract: TargetConfigurations absent entirely (not merely invalid) is
    # rejected by the service's own structural validation. Local SDK validation is
    # disabled so the incomplete request actually reaches the service instead of boto3
    # raising ParamValidationError before any request is made.
    code, message = _error(
        lambda: ec2_unvalidated.modify_reserved_instances(
            ReservedInstancesIds=["1234abcd-1234-abcd-1234-abcdef123456"]
        )
    )
    assert code == "MissingParameter", f"expected MissingParameter, got {code}"
    assert message == "TargetReservedInstancesConfigurationSet", message

    # server-side contract: a well-formed request for a nonexistent id is rejected for a
    # different, specific reason than the missing-parameter case above.
    err, message = _error(
        lambda: ec2.modify_reserved_instances(
            ReservedInstancesIds=["1234abcd-1234-abcd-1234-abcdef123456"],
            TargetConfigurations=[
                {"AvailabilityZone": zone, "InstanceCount": 1, "InstanceType": "t3.micro"}
            ],
        )
    )
    assert err == "InvalidInput", f"expected InvalidInput, got {err}"
    assert message == " Invalid value for 'reservedInstancesIds'. Reserved Instance 1234abcd-1234-abcd-1234-abcdef123456 is not found.", message
    assert err != code, "a missing required field and a bogus resource id must not share a code"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _no_validate_client(ctx, service: str):
    """A client with client-side parameter validation disabled, so an omitted required
    field is actually sent to the TARGET and the SERVER's rejection is observed, instead of
    boto3 raising a local ParamValidationError before any request is made. Built through
    `ctx.client(..., config=...)` so the config is MERGED over the runner's base config and
    the client keeps the target's endpoint, credentials, region and TLS settings."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

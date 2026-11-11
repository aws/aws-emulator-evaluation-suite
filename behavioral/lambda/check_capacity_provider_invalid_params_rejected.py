"""capacity-provider-invalid-params-rejected."""
from __future__ import annotations

from typing import Any, Callable, Tuple

from behavioral_harness import tags

CHECK = "capacity-provider-invalid-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider with a nonexistent VPC and operator role and contradictory instance
    filters is InvalidParameterValueException with the exact operator-role message, and GetCapacityProvider
    then answers ResourceNotFoundException, so nothing was created."""
    lam = ctx.client("lambda")
    if not hasattr(lam, "create_capacity_provider"):
        raise AssertionError("unreachable: CreateCapacityProvider not present in installed boto3 lambda model")

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    cp_name = ctx.unique_name("sim2real-cp-")
    fake_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-nonexistent-role-')}"

    def _attempt() -> None:
        lam.create_capacity_provider(
            CapacityProviderName=cp_name,
            VpcConfig={
                "SubnetIds": ["subnet-0123456789abcdef0"],
                "SecurityGroupIds": ["sg-0123456789abcdef0"],
            },
            PermissionsConfig={"CapacityProviderOperatorRoleArn": fake_role_arn},
            InstanceRequirements={
                "AllowedInstanceTypes": ["m5.large"],
                "ExcludedInstanceTypes": ["m5.large"],
            },
        )
        # Reached only when the create is accepted: delete it so nothing billable leaks.
        ctx.on_cleanup(lambda: lam.delete_capacity_provider(CapacityProviderName=cp_name))

    code, message = _client_error(_attempt, "CreateCapacityProvider with a nonexistent VPC/role and contradictory instance-type filters")
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException, got {code!r}"
    )
    assert message == (
        "The operator role is invalid or doesn't have sufficient permissions. "
        "Verify the role and permissions and try again."
    ), f"unexpected CreateCapacityProvider message: {message!r}"

    # Independent read at the destination: the rejected create must not have left a capacity
    # provider behind under this name, e.g. from a service that validates asynchronously and
    # rejects the request but still records a stub entry.
    get_code, get_message = _client_error(
        lambda: lam.get_capacity_provider(CapacityProviderName=cp_name),
        f"GetCapacityProvider of the rejected {cp_name!r}",
    )
    assert get_code == "ResourceNotFoundException", (
        f"rejected CreateCapacityProvider still left {cp_name!r} gettable "
        f"(GetCapacityProvider returned {get_code!r}, expected ResourceNotFoundException)"
    )
    cp_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:capacity-provider:{cp_name}"
    assert get_message == (
        f"Capacity provider not found: {cp_arn}. Check that the ARN is correct and the "
        "capacity provider exists in this Region."
    ), f"unexpected GetCapacityProvider message: {get_message!r}"


def _client_error(fn: Callable[[], Any], what: str) -> Tuple[str, str]:
    """Return (code, message) of the ClientError ``fn`` raises; a success is a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"{what} succeeded instead of being rejected")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

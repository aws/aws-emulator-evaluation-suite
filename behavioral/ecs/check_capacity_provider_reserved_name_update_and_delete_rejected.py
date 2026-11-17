"""capacity-provider-reserved-name-update-and-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-reserved-name-update-and-delete-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED with {result!r}")


_RESERVED = (
    "ClientException",
    "The specified capacity provider is reserved and cannot be modified by this operation. "
    "Specify a valid name or ARN and try again.",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider and DeleteCapacityProvider both refuse the built-in FARGATE
    provider as reserved, while it remains describable and usable throughout."""
    ecs = ctx.client("ecs")

    # --- positive control: the built-in provider is a real, describable name ---
    before = ecs.describe_capacity_providers(capacityProviders=["FARGATE"])["capacityProviders"]
    assert before and before[0]["name"] == "FARGATE" and before[0]["status"] == "ACTIVE", (
        f"positive control: FARGATE is not describable as ACTIVE: {before!r}"
    )

    error = _error(
        lambda: ecs.update_capacity_provider(
            name="FARGATE",
            autoScalingGroupProvider={"managedScaling": {"status": "DISABLED"}},
        )
    )
    assert error == _RESERVED, f"UpdateCapacityProvider(FARGATE): expected {_RESERVED!r}, got {error!r}"

    error = _error(lambda: ecs.delete_capacity_provider(capacityProvider="FARGATE"))
    assert error == _RESERVED, f"DeleteCapacityProvider(FARGATE): expected {_RESERVED!r}, got {error!r}"

    # --- the rejected calls left the built-in provider exactly as it was ---
    after = ecs.describe_capacity_providers(capacityProviders=["FARGATE"])["capacityProviders"]
    assert after and after[0]["name"] == "FARGATE" and after[0]["status"] == "ACTIVE", (
        f"a rejected call changed the built-in provider: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

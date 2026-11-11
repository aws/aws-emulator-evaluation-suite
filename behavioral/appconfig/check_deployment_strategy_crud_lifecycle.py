"""deployment-strategy-crud-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-strategy-crud-lifecycle"
GROUP = 'deployment-strategy'
SERVICES = ['appconfig']


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _unless_gone(fn):
    """Teardown wrapper: a resource the check already deleted is not a teardown failure."""

    def _run():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    return _run


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deployment strategy create->get->update->delete->get(404) state machine holds; the
    identifier is unusable for both reads and mutations once deleted."""
    ac = ctx.client("appconfig")
    created = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=10,
        GrowthFactor=25,
        FinalBakeTimeInMinutes=5,
        ReplicateTo="NONE",
        Tags={"sim2real-check": "deployment-strategy-crud-lifecycle"},
    )
    ds_id = created["Id"]
    ctx.on_cleanup(_unless_gone(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id)))
    assert created["DeploymentDurationInMinutes"] == 10, (
        f"expected DeploymentDurationInMinutes=10 on create, got {created['DeploymentDurationInMinutes']!r}"
    )
    assert created["GrowthFactor"] == 25, f"expected GrowthFactor=25 on create, got {created['GrowthFactor']!r}"

    updated = ac.update_deployment_strategy(DeploymentStrategyId=ds_id, GrowthFactor=50)
    assert updated["GrowthFactor"] == 50, f"expected GrowthFactor=50 after update, got {updated['GrowthFactor']!r}"

    got = ac.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got["GrowthFactor"] == 50, f"expected GrowthFactor=50 on independent read, got {got['GrowthFactor']!r}"
    # Untouched field must survive the partial update.
    assert got["DeploymentDurationInMinutes"] == 10, (
        f"partial update must not disturb DeploymentDurationInMinutes, got {got['DeploymentDurationInMinutes']!r}"
    )

    ac.delete_deployment_strategy(DeploymentStrategyId=ds_id)

    not_found = f"DeploymentStrategy with Id {ds_id} could not be found."
    read_code, read_message = _client_error(
        lambda: ac.get_deployment_strategy(DeploymentStrategyId=ds_id)
    )
    assert read_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted strategy, got {read_code!r}"
    )
    assert read_message == not_found, f"expected {not_found!r}, got {read_message!r}"

    # A mutation on the dead id must also fail, not just a read.
    mutate_code, mutate_message = _client_error(
        lambda: ac.update_deployment_strategy(DeploymentStrategyId=ds_id, GrowthFactor=75)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted strategy, got {mutate_code!r}"
    )
    assert mutate_message == not_found, f"expected {not_found!r}, got {mutate_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

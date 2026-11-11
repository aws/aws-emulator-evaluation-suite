"""invalid-parameter-task-definition-ops."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-parameter-task-definition-ops"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises: accepting
    input AWS refuses is reported as such, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _teardown_task_definition(ecs, arn):
    """Deregister then delete; a revision the check already deleted refuses the deregister."""
    try:
        ecs.deregister_task_definition(taskDefinition=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ClientException":
            raise
    ecs.delete_task_definitions(taskDefinitions=[arn])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Malformed task-definition parameters and families return their documented error codes on
    Register/Describe/Deregister/DeleteTaskDefinitions and the two List ops, each paired with a
    positive control on the same operation so a target rejecting every call cannot pass."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-invparam-")

    # Positive control: RegisterTaskDefinition succeeds on a well-formed definition.
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _teardown_task_definition(ecs, arn))
    assert td["status"] == "ACTIVE", f"positive control: RegisterTaskDefinition returned {td['status']!r}, expected ACTIVE"

    error = _error(
        lambda: ecs.register_task_definition(
            family=ctx.unique_name("taskdef-"),
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "cpu": -100,
                    "memory": 128,
                    "essential": True,
                }
            ],
        )
    )
    expected = ("ClientException", "Invalid 'cpu' setting for container 'app'.")
    assert error == expected, f"RegisterTaskDefinition: expected {expected!r}, got {error!r}"

    # Positive control: DescribeTaskDefinition succeeds for the real arn.
    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["taskDefinitionArn"] == arn, (
        f"positive control: DescribeTaskDefinition returned {described['taskDefinitionArn']!r}, expected {arn!r}"
    )

    error = _error(lambda: ecs.describe_task_definition(taskDefinition="not a valid @@@ identifier"))
    expected = ("ClientException", "Family contains invalid characters.")
    assert error == expected, f"DescribeTaskDefinition: expected {expected!r}, got {error!r}"

    # Positive control: the real family is visible through both listing operations.
    arns = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert arn in arns, f"positive control: ListTaskDefinitions(familyPrefix={family!r}) did not include {arn!r}: {arns!r}"

    families = ecs.list_task_definition_families(familyPrefix=family)["families"]
    assert family in families, (
        f"positive control: ListTaskDefinitionFamilies(familyPrefix={family!r}) did not include the family: {families!r}"
    )

    error = _error(
        lambda: ecs.deregister_task_definition(taskDefinition="not a valid @@@ identifier")
    )
    expected = ("InvalidParameterException", "Revision is missing")
    assert error == expected, f"DeregisterTaskDefinition: expected {expected!r}, got {error!r}"

    error = _error(
        lambda: ecs.delete_task_definitions(
            taskDefinitions=[f"not-a-valid-identifier-{i}" for i in range(11)]
        )
    )
    expected = ("InvalidParameterException", "Size of TaskDefinition references list cannot exceed 10")
    assert error == expected, f"DeleteTaskDefinitions: expected {expected!r}, got {error!r}"

    error = _error(lambda: ecs.list_task_definitions(maxResults=0))
    expected = ("InvalidParameterException", "Max results can not be lesser than 1")
    assert error == expected, f"ListTaskDefinitions: expected {expected!r}, got {error!r}"

    error = _error(lambda: ecs.list_task_definition_families(maxResults=0))
    expected = ("InvalidParameterException", "Max results can not be lesser than 1")
    assert error == expected, f"ListTaskDefinitionFamilies: expected {expected!r}, got {error!r}"

    # Positive control: Deregister and Delete succeed on the real, well-formed task definition.
    deregistered = ecs.deregister_task_definition(taskDefinition=arn)["taskDefinition"]
    assert deregistered["status"] == "INACTIVE", (
        f"positive control: DeregisterTaskDefinition returned {deregistered['status']!r}, expected INACTIVE"
    )

    deleted = ecs.delete_task_definitions(taskDefinitions=[arn])
    failures = deleted.get("failures", [])
    assert not failures, f"positive control: DeleteTaskDefinitions failed on the real arn: {failures!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

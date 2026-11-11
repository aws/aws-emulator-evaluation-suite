"""register-taskdef-invalid-resource-limits."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "register-taskdef-invalid-resource-limits"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition rejects a container whose memoryReservation exceeds its memory
    hard limit, while the same shape with reservation below the limit registers cleanly."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-badres-")

    # overly-permissive boundary: reservation > hard limit is nonsensical.
    code, message = _refusal(
        lambda: ecs.register_task_definition(
            family=family,
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "essential": True,
                    "memory": 128,
                    "memoryReservation": 256,
                }
            ],
        )
    )
    # Real ECS rejects this internally-inconsistent resource spec with the
    # generic ClientException (not InvalidParameterException), a server-side
    # rejection of the nonsensical reservation > hard limit.
    assert code == "ClientException", (
        f"expected a rejection for memoryReservation > memory, got {code}"
    )
    assert message == "Invalid setting for container 'app'. 'memory' must be greater than or equal to 'memoryReservation'.", f"refusal message {message!r}"

    # sanity: the same shape with sane values registers fine.
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "memory": 256,
                "memoryReservation": 128,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))

    # terminal read: an independent DescribeTaskDefinition, not the register response.
    described = ecs.describe_task_definition(taskDefinition=td["taskDefinitionArn"])["taskDefinition"]
    assert described["status"] == "ACTIVE", f"expected ACTIVE, got {described['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

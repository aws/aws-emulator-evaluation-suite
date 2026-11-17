"""register-job-definition-rejects-oversized-definition."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


CHECK = "register-job-definition-rejects-oversized-definition"
GROUP = "validation"
SERVICES = ["batch"]

_RESOURCE_REQUIREMENTS = [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}]


def _container_properties(padding_bytes: int) -> dict:
    return {
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "resourceRequirements": _RESOURCE_REQUIREMENTS,
        "environment": [{"name": "PADDING", "value": "A" * padding_bytes}],
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterJobDefinition rejects a definition over the 24 KiB size limit with
    ClientException and registers nothing; a definition under the limit succeeds."""
    batch = ctx.client("batch")
    oversized_name = ctx.unique_name("sim2real-batch-jd-big-")
    oversized_request = {
        "jobDefinitionName": oversized_name,
        "type": "container",
        "containerProperties": _container_properties(40000),
    }
    # The reported size is this request's own compact-JSON byte length, floored to whole KB.
    reported_kb = len(json.dumps(oversized_request, separators=(",", ":"))) // 1024

    code, message, request_id = _error_code(lambda: batch.register_job_definition(**oversized_request))
    assert code == "ClientException", f"expected ClientException for an oversized definition, got {code!r}"
    expected_message = (
        f"Error executing request, Exception : JobDefinition size must be less than 24 KB, "
        f"got {reported_kb} KB., RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden effect did not happen: no job definition with that name was registered.
    listed = batch.describe_job_definitions(jobDefinitionName=oversized_name)["jobDefinitions"]
    assert listed == [], f"expected no job definition registered under {oversized_name!r}, got {listed!r}"

    # Positive control: the same shape, under the limit, succeeds.
    small_name = ctx.unique_name("sim2real-batch-jd-small-")
    registered = batch.register_job_definition(
        jobDefinitionName=small_name,
        type="container",
        containerProperties=_container_properties(100),
    )
    arn = registered["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=arn))
    described = batch.describe_job_definitions(jobDefinitionName=small_name)["jobDefinitions"]
    assert len(described) == 1, f"expected exactly one registered definition, got {described!r}"
    assert described[0]["jobDefinitionArn"] == arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

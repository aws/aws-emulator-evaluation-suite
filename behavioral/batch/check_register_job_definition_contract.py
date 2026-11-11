"""register-job-definition-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-job-definition-contract"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterJobDefinition creates a new ACTIVE revision with the exact properties given, and rejects an incomplete type=container definition."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jd-")

    resp = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        retryStrategy={"attempts": 2},
        timeout={"attemptDurationSeconds": 60},
        containerProperties={
            "image": "busybox:1.36",
            "command": ["echo", "hello-batch"],
            "environment": [{"name": "FOO", "value": "bar"}],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
    )
    arn = resp["jobDefinitionArn"]
    assert resp["jobDefinitionName"] == name, f"expected jobDefinitionName {name!r}, got {resp['jobDefinitionName']!r}"
    assert resp["revision"] == 1, f"expected the first registration to be revision 1, got {resp['revision']!r}"
    ctx.on_cleanup(lambda: _best_effort_deregister(batch, arn))

    described = batch.describe_job_definitions(jobDefinitions=[arn])["jobDefinitions"][0]
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"
    assert described["type"] == "container", f"expected type container, got {described['type']!r}"
    assert described["retryStrategy"]["attempts"] == 2, (
        f"expected retryStrategy.attempts 2, got {described['retryStrategy']['attempts']!r}"
    )
    assert described["timeout"]["attemptDurationSeconds"] == 60, (
        f"expected timeout.attemptDurationSeconds 60, got {described['timeout']['attemptDurationSeconds']!r}"
    )
    assert described["containerProperties"]["image"] == "busybox:1.36", (
        f"expected containerProperties.image 'busybox:1.36', got {described['containerProperties']['image']!r}"
    )
    assert described["containerProperties"]["command"] == ["echo", "hello-batch"], (
        f"expected containerProperties.command ['echo', 'hello-batch'], "
        f"got {described['containerProperties']['command']!r}"
    )
    assert {"name": "FOO", "value": "bar"} in described["containerProperties"]["environment"], (
        f"expected environment to contain FOO=bar, got {described['containerProperties']['environment']!r}"
    )

    # Re-registering the same name creates a new, independent revision rather than mutating rev 1.
    resp2 = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "command": ["echo", "second-revision"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
    )
    arn2 = resp2["jobDefinitionArn"]
    assert resp2["revision"] == 2, f"expected the re-registration to be revision 2, got {resp2['revision']!r}"
    ctx.on_cleanup(lambda: _best_effort_deregister(batch, arn2))
    rev1_still = batch.describe_job_definitions(jobDefinitions=[arn])["jobDefinitions"][0]
    assert rev1_still["containerProperties"]["command"] == ["echo", "hello-batch"], (
        f"revision 1 was mutated by registering revision 2: command is now "
        f"{rev1_still['containerProperties']['command']!r}"
    )

    # Negative: type=container requires containerProperties; omitting it is rejected, and the
    # rejected call must never have created a job definition under that name.
    bad_name = ctx.unique_name("sim2real-batch-jd-bad-")
    code, message, request_id = _error_code(
        lambda: batch.register_job_definition(jobDefinitionName=bad_name, type="container")
    )
    assert code == "ClientException", f"expected ClientException for missing containerProperties, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected = (
        "Error executing request, Exception : ECS ContainerProperties, ecsProperties, or eksProperties is "
        f"required when using type container., RequestId: {request_id}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"
    leftover = batch.describe_job_definitions(jobDefinitionName=bad_name)["jobDefinitions"]
    assert leftover == [], f"the rejected registration must not have created a job definition, got {leftover!r}"


def _error_code(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message, RequestId). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message"), err.response["ResponseMetadata"].get("RequestId")
    raise AssertionError(f"expected registration to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_deregister(batch, arn: str) -> None:
    batch.deregister_job_definition(jobDefinition=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

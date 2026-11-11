"""deregister-job-definition-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deregister-job-definition-contract"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterJobDefinition flips ACTIVE->INACTIVE and rejects a malformed identifier."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jd-")

    resp = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "command": ["echo", "hello"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
    )
    arn = resp["jobDefinitionArn"]
    revision = resp["revision"]
    assert revision == 1, f"expected the first registration to be revision 1, got {revision}"
    ctx.on_cleanup(lambda: _best_effort_deregister(batch, arn))

    active = batch.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    assert len(active) == 1 and active[0]["jobDefinitionArn"] == arn, (
        f"expected exactly one ACTIVE definition with arn {arn}, got {active}"
    )
    assert active[0]["status"] == "ACTIVE", f"expected status ACTIVE, got {active[0]['status']}"
    assert active[0]["revision"] == 1, f"expected revision 1, got {active[0]['revision']}"

    # Negative: a malformed job definition identifier (invalid name characters) is rejected.
    malformed = "!! not a valid name !!:1"
    code, message = _error(lambda: batch.deregister_job_definition(jobDefinition=malformed))
    assert code == "ClientException", f"expected ClientException for malformed identifier, got {code}"
    expected_message = f"Provided name {malformed} is not supported pattern[a-zA-Z_0-9-]{{1,128}}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The real, valid job definition is unaffected by the rejected call.
    still_active = batch.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    assert len(still_active) == 1 and still_active[0]["status"] == "ACTIVE", (
        f"expected the real definition to remain ACTIVE and unaffected, got {still_active}"
    )

    # Positive control: deregistering the real revision succeeds and flips status to INACTIVE.
    batch.deregister_job_definition(jobDefinition=arn)
    still_listed = batch.describe_job_definitions(jobDefinitions=[arn])["jobDefinitions"]
    assert len(still_listed) == 1, f"expected exactly one definition for arn {arn}, got {still_listed}"
    assert still_listed[0]["status"] == "INACTIVE", f"expected INACTIVE after deregister, got {still_listed[0]}"

    no_longer_active = batch.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    assert no_longer_active == [], (
        f"expected no ACTIVE definitions named {name} after deregister, got {no_longer_active}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _best_effort_deregister(batch, arn: str) -> None:
    batch.deregister_job_definition(jobDefinition=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

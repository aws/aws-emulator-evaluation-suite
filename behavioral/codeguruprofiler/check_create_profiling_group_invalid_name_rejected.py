"""create-profiling-group-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-profiling-group-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup rejects a profilingGroupName that violates the
    ^[\\w-]+$ pattern with ValidationException, creating nothing; a valid name
    in the same account still succeeds."""
    cgp = ctx.client("codeguruprofiler")
    invalid_name = ctx.unique_name("sim2real behav cgp!") + " invalid"

    code, message = _error_code(
        lambda: cgp.create_profiling_group(
            profilingGroupName=invalid_name,
            agentOrchestrationConfig={"profilingEnabled": True},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{invalid_name}' at 'profilingGroupName' failed "
        r"to satisfy constraint: Member must satisfy regular expression pattern: [\w-]+"
    )
    assert message == expected_message, (message, expected_message)

    # Effect absent: nothing was created under that (invalid) name.
    names = set()
    next_token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = cgp.list_profiling_groups(**kwargs)
        names.update(page.get("profilingGroupNames", []))
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert invalid_name not in names, f"{invalid_name!r} unexpectedly appears in {sorted(names)}"

    # Positive control: a validly named profiling group still creates successfully.
    valid_name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=valid_name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real-test"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=valid_name))

    # Terminal read is independent of the mutating call: describe, not the create response.
    described = cgp.describe_profiling_group(profilingGroupName=valid_name)["profilingGroup"]
    assert described["name"] == valid_name, (
        f"expected describe_profiling_group to reflect {valid_name!r}, got {described.get('name')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

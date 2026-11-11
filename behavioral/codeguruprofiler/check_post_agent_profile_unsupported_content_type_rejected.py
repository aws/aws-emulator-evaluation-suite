"""post-agent-profile-unsupported-content-type-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "post-agent-profile-unsupported-content-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PostAgentProfile with contentType text/plain and a bare-symbol body fails with a ValidationException for a
    non-struct root and leaves latestAgentProfileReportedAt unset, while application/json with an empty object
    fails with a distinct ValidationException.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=str(uuid.uuid4()), tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    before_status = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"].get(
        "profilingStatus", {}
    ) or {}
    assert "latestAgentProfileReportedAt" not in before_status, (
        f"expected a freshly created profiling group to have no agent-reported status, got {before_status!r}"
    )

    unsupported_err = _error(
        lambda: cgp.post_agent_profile(
            profilingGroupName=name,
            agentProfile=b"not-a-profile",
            contentType="text/plain",
        )
    )
    assert unsupported_err["Code"] == "ValidationException", (
        f"expected ValidationException for an unsupported contentType, got {unsupported_err['Code']!r}"
    )
    # AWS does not refuse the Content-Type itself: it parses the body and refuses
    # the bare symbol as a profile whose root is not a struct.
    expected_unsupported = (
        "Invalid agent profile: Unexpected type for profile root. Expected STRUCT, got SYMBOL.."
    )
    assert unsupported_err["Message"] == expected_unsupported, (
        unsupported_err["Message"], expected_unsupported
    )

    # effect absent: the rejected submission did not register as a received profile
    after_status = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"].get(
        "profilingStatus", {}
    ) or {}
    assert "latestAgentProfileReportedAt" not in after_status, (
        f"expected the rejected submission to leave profilingStatus untouched, got {after_status!r}"
    )

    # contrast: a supported content type is validated for payload content, and the
    # empty object draws a different complaint from the bare symbol above.
    supported_err = _error(
        lambda: cgp.post_agent_profile(
            profilingGroupName=name, agentProfile=b"{}", contentType="application/json"
        )
    )
    assert supported_err["Code"] == "ValidationException", (
        f"a supported Content-Type with an empty JSON object must fail as ValidationException, "
        f"got {supported_err['Code']!r}"
    )
    expected_supported = "Invalid agent profile: Profile must contain a start field.."
    assert supported_err["Message"] == expected_supported, (
        supported_err["Message"], expected_supported
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

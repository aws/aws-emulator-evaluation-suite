"""post-agent-profile-invalid-content-type-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "post-agent-profile-invalid-content-type-rejected"
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
    """PostAgentProfile with an unsupported Content-Type and a bare-symbol body fails with a ValidationException
    for a non-struct root and leaves profilingStatus unset, while application/json with an empty object fails
    with a distinct ValidationException.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-post-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=token,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real": "post-agent-profile-invalid-content-type-rejected"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    before = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    before_reported_at = before.get("profilingStatus", {}).get("latestAgentProfileReportedAt")
    assert before_reported_at is None, f"expected no agent profile reported yet, got {before_reported_at!r}"

    unsupported_err = _error(
        lambda: cgp.post_agent_profile(
            profilingGroupName=name,
            agentProfile=b"not-a-profile",
            contentType="text/plain",
        )
    )
    assert unsupported_err["Code"] == "ValidationException", (
        f"expected ValidationException for an unsupported Content-Type, got {unsupported_err['Code']!r}"
    )
    # AWS does not refuse the Content-Type itself: it parses the body and refuses
    # the bare symbol as a profile whose root is not a struct.
    expected_unsupported = (
        "Invalid agent profile: Unexpected type for profile root. Expected STRUCT, got SYMBOL.."
    )
    assert unsupported_err["Message"] == expected_unsupported, (
        unsupported_err["Message"], expected_unsupported
    )

    after_reject = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    after_reject_reported_at = after_reject.get("profilingStatus", {}).get("latestAgentProfileReportedAt")
    assert after_reject_reported_at is None, (
        f"rejected agentProfile must not register as reported, got {after_reject_reported_at!r}"
    )

    # contrast: a supported content type is validated for payload content, and the
    # empty object draws a different complaint from the bare symbol above.
    supported_err = _error(
        lambda: cgp.post_agent_profile(
            profilingGroupName=name,
            agentProfile=b"{}",
            contentType="application/json",
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

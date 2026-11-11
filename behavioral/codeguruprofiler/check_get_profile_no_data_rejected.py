"""get-profile-no-data-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-profile-no-data-rejected"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetProfile with period on a group that never received agent data fails with ResourceNotFoundException 'No
    profiles found for the requested time range!', while DescribeProfilingGroup returns the group with no
    profile reported.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=str(uuid.uuid4()), tags={"env": "sim2real"}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    try:
        cgp.get_profile(profilingGroupName=name, period="PT5M")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException, got {code}: {message}"
        )
        assert message == "No profiles found for the requested time range!", message
    else:
        raise AssertionError("GetProfile unexpectedly succeeded for a group with no profile data")

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["name"] == name, described
    assert described.get("profilingStatus", {}).get("latestAgentProfileReportedAt") is None, described


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

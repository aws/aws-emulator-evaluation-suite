"""get-policy-no-policy-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-policy-no-policy-not-found"
GROUP = "error-semantics"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))
    return ("ok", result)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicy on a profiling group with no permission succeeds without policy or revisionId fields, while
    GetPolicy on a nonexistent group fails with ResourceNotFoundException and its exact message.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-nopolicy-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=token, tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    # sanity: the group itself is visible
    group_arn = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]["arn"]

    response = cgp.get_policy(profilingGroupName=name)
    assert "policy" not in response, response
    assert "revisionId" not in response, response

    # contrast: a genuinely missing profiling group DOES raise ResourceNotFoundException
    missing_name = ctx.unique_name("sim2real-cgp-nopolicy-missing-")
    outcome, payload = _error_code(lambda: cgp.get_policy(profilingGroupName=missing_name))
    assert outcome == "error", (outcome, payload)
    account_id = group_arn.split(":")[4]
    assert payload == (
        "ResourceNotFoundException",
        f"No profiling group with accountId: {account_id}; name: {missing_name} was found.",
    ), payload


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

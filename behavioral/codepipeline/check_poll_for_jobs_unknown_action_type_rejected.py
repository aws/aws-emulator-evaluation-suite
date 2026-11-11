"""poll-for-jobs-unknown-action-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "poll-for-jobs-unknown-action-type-rejected"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PollForJobs for a real, registered Custom action type succeeds (positive
    control); the identical call for a Custom action type that was never created ->
    ActionTypeNotFoundException."""
    ev = ctx.client("codepipeline")
    category, version = "Build", "1"
    provider = ctx.unique_name("sim2real-behav-ca-")
    ev.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        tags=[{"key": "sim2real:created-by", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ev.delete_custom_action_type(category=category, provider=provider, version=version))

    positive = ev.poll_for_jobs(actionTypeId={"category": category, "owner": "Custom", "provider": provider, "version": version})
    assert positive["jobs"] == [], f"expected no jobs for a freshly-registered action type, got {positive['jobs']!r}"

    missing = ctx.unique_name("sim2real-behav-ca-none-")
    error = _error(lambda: ev.poll_for_jobs(actionTypeId={"category": category, "owner": "Custom", "provider": missing, "version": version}))
    assert error.get("Code") == "ActionTypeNotFoundException", f"expected ActionTypeNotFoundException, got {error!r}"
    expected_message = (
        f"ActionType (Category: '{category}', Owner: 'Custom', Provider: '{missing}', "
        f"Version: '{version}') is not available"
    )
    assert error.get("Message") == expected_message, f"expected message {expected_message!r}, got {error.get('Message')!r}"


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

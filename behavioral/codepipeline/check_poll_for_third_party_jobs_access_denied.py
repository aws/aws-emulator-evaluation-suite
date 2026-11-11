"""poll-for-third-party-jobs-access-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "poll-for-third-party-jobs-access-denied"
GROUP = 'overly-permissive'
SERVICES = ['codepipeline']

@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PollForThirdPartyJobs from a standard account fails with AccessDeniedException and its exact message
    rather than an empty job list, while a preceding CodePipeline call succeeds.
    """
    cp = ctx.client("codepipeline")

    # Positive control: an ordinary, always-permitted call must succeed on the
    # same client/credentials before the negative is trusted.
    cp.list_pipelines()

    provider = ctx.unique_name("sim2real-behav-ca-3p-")
    error = _error(
        lambda: cp.poll_for_third_party_jobs(
            actionTypeId={
                "category": "Source",
                "owner": "ThirdParty",
                "provider": provider,
                "version": "1",
            }
        )
    )
    assert error.get("Code") == "AccessDeniedException", f"expected AccessDeniedException for a non-partner caller, got {error!r}"
    # AWS's own refusal text, asserted verbatim.
    expected_message = (
        "Not whitelisted for accessing ActionType.Category='Source' ActionType.Owner='ThirdParty' "
        f"ActionType.Provider='{provider}' ActionType.Version='1'"
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

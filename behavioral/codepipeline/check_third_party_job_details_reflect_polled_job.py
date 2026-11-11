"""third-party-job-details-reflect-polled-job."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "third-party-job-details-reflect-polled-job"
GROUP = "data-plane"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PollForThirdPartyJobs from a standard account fails with AccessDeniedException and GetThirdPartyJobDetails
    for a never-issued jobId with JobNotFoundException, each with its exact message, while PollForJobs on a
    Custom type succeeds.
    """
    cp = ctx.client("codepipeline")

    # --- positive control: this account's own IAM principal can genuinely poll
    # its own Custom-owned action type via the self-service PollForJobs API, so
    # the negatives below cannot pass merely because codepipeline access itself
    # is broken.
    custom_type = _create_custom_action_type(ctx, "Build")
    custom_poll = cp.poll_for_jobs(actionTypeId=custom_type, maxBatchSize=1)
    assert custom_poll["jobs"] == [], custom_poll

    bogus_action_type_id = {
        "category": "Build",
        "owner": "ThirdParty",
        "provider": "Sim2RealNoSuchProvider",
        "version": "1",
    }
    poll_code, poll_message = _error(
        lambda: cp.poll_for_third_party_jobs(actionTypeId=bogus_action_type_id, maxBatchSize=1)
    )
    # Real AWS rejects non-partner callers outright for this partner-restricted
    # operation, before any action-type-existence check is reached.
    assert poll_code == "AccessDeniedException", poll_code
    assert poll_message == _not_allowed_message(bogus_action_type_id), poll_message

    bogus_job_id = str(uuid.uuid4())
    details_code, details_message = _error(
        lambda: cp.get_third_party_job_details(
            jobId=bogus_job_id, clientToken="sim2real-bogus-client-token"
        )
    )
    assert details_code == "JobNotFoundException", details_code
    assert details_message == f"Job with id '{bogus_job_id}' does not exist.", details_message


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _not_allowed_message(action_type_id: dict) -> str:
    """AWS's exact refusal text for a non-partner PollForThirdPartyJobs call."""
    return (
        "Not whitelisted for accessing "
        f"ActionType.Category='{action_type_id['category']}' "
        f"ActionType.Owner='{action_type_id['owner']}' "
        f"ActionType.Provider='{action_type_id['provider']}' "
        f"ActionType.Version='{action_type_id['version']}'"
    )


def _create_custom_action_type(ctx, category: str) -> dict:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("Sim2RealBuild-")[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
    )
    ctx.on_cleanup(
        lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version)
    )
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

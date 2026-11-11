"""third-party-job-nonce-single-use-visibility."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "third-party-job-nonce-single-use-visibility"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PollForThirdPartyJobs from a standard account fails with AccessDeniedException, and
    AcknowledgeThirdPartyJob and GetThirdPartyJobDetails for an unknown job fail with JobNotFoundException,
    each with its exact message.
    """
    cp = ctx.client("codepipeline")
    custom_type = _create_custom_action_type(ctx, "Build")

    # --- positive control: the Custom-owned type is genuinely poll-able by
    # this account's own IAM principal via the self-service PollForJobs API.
    custom_poll = cp.poll_for_jobs(actionTypeId=custom_type, maxBatchSize=1)
    assert custom_poll["jobs"] == [], custom_poll

    # --- negative #1: PollForThirdPartyJobs is off-limits to a standard
    # account's IAM principal regardless of which actionTypeId is named.
    third_party_type = dict(custom_type, owner="ThirdParty")
    code, message = _error(
        lambda: cp.poll_for_third_party_jobs(actionTypeId=third_party_type, maxBatchSize=1)
    )
    assert code == "AccessDeniedException", code
    assert message == _not_allowed_message(third_party_type), message

    # --- negative #2: AcknowledgeThirdPartyJob against a job that was never
    # created (well-formed jobId, bogus nonce/clientToken) is rejected on
    # existence -- unlike PollForThirdPartyJobs (denied on authorization before
    # any lookup), Acknowledge validates the job id itself first.
    fake_job_id = str(uuid.uuid4())
    code2, message2 = _error(
        lambda: cp.acknowledge_third_party_job(
            jobId=fake_job_id, nonce="0", clientToken="does-not-exist"
        )
    )
    assert code2 == "JobNotFoundException", code2
    assert message2 == f"Job with id '{fake_job_id}' does not exist.", message2

    # --- effect absent: the rejected acknowledgement left no phantom job
    # behind -- an independent read (GetThirdPartyJobDetails, a different
    # operation) on the same id is rejected the same way, not treated as
    # existing or as a different failure mode.
    code3, message3 = _error(
        lambda: cp.get_third_party_job_details(jobId=fake_job_id, clientToken="does-not-exist")
    )
    assert code3 == "JobNotFoundException", code3
    assert message3 == f"Job with id '{fake_job_id}' does not exist.", message3


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    provider = f"S2R{category[:2]}{_short_id()}"[:35]
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


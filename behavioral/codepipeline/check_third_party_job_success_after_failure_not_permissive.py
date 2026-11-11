"""third-party-job-success-after-failure-not-permissive."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "third-party-job-success-after-failure-not-permissive"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A non-partner caller gets AccessDeniedException from PollForThirdPartyJobs for every listed
    ThirdParty action type; both job-result APIs reject an unknown job id with JobNotFoundException;
    for a polled partner job, success after failure fails with InvalidJobStateException."""
    from botocore.exceptions import ClientError

    cp = ctx.client("codepipeline")

    listed = cp.list_action_types(actionOwnerFilter="ThirdParty")
    assert "actionTypes" in listed
    third_party_types = listed["actionTypes"]
    assert isinstance(third_party_types, list)
    assert third_party_types, "expected AWS to list at least one built-in ThirdParty action type"

    discovered_job = None
    for action_type in third_party_types:
        try:
            polled = cp.poll_for_third_party_jobs(actionTypeId=action_type["id"], maxBatchSize=1)
        except ClientError as err:
            # PollForThirdPartyJobs is partner-restricted: a non-partner caller is refused.
            code = err.response["Error"]["Code"]
            assert code == "AccessDeniedException", (
                f"unexpected code polling actionTypeId={action_type['id']}: {code}"
            )
            message = err.response["Error"].get("Message")
            assert message == _not_allowed_message(action_type["id"]), message
            continue
        assert "jobs" in polled
        assert isinstance(polled["jobs"], list)
        if polled["jobs"]:
            discovered_job = polled["jobs"][0]
            break

    # A syntactically valid but nonexistent job id is rejected by both terminal-result APIs.
    fake_job_id = str(uuid.uuid4())
    fake_client_token = "fake-client-token-" + ctx.unique_name("tok")
    fail_notfound_code, fail_notfound_message = _error(
        lambda: cp.put_third_party_job_failure_result(
            jobId=fake_job_id,
            clientToken=fake_client_token,
            failureDetails={"type": "JobFailed", "message": "no such job"},
        )
    )
    assert fail_notfound_code == "JobNotFoundException", f"unexpected code: {fail_notfound_code}"
    assert fail_notfound_message == f"Job with id '{fake_job_id}' does not exist.", fail_notfound_message
    success_notfound_code, success_notfound_message = _error(
        lambda: cp.put_third_party_job_success_result(jobId=fake_job_id, clientToken=fake_client_token)
    )
    assert success_notfound_code == "JobNotFoundException", f"unexpected code: {success_notfound_code}"
    assert success_notfound_message == f"Job with id '{fake_job_id}' does not exist.", success_notfound_message

    if discovered_job is None:
        # A non-partner account can never poll a job, so the completed-job path is unreachable.
        return

    job_id = discovered_job["jobId"]
    client_token = discovered_job["clientId"]
    details = cp.get_third_party_job_details(jobId=job_id, clientToken=client_token)
    nonce = details["jobDetails"]["nonce"]
    cp.acknowledge_third_party_job(jobId=job_id, nonce=nonce, clientToken=client_token)

    # positive control: completing the job via failure succeeds and is the normal
    # terminal path.
    cp.put_third_party_job_failure_result(
        jobId=job_id,
        clientToken=client_token,
        failureDetails={"type": "JobFailed", "message": "behavioral fidelity check failure"},
    )

    # break exactly one thing: attempt to also complete the same, already-failed
    # job via success.
    code, _message = _error(
        lambda: cp.put_third_party_job_success_result(jobId=job_id, clientToken=client_token)
    )
    # message not pinned: this branch runs only in a partner-registered account.
    assert code == "InvalidJobStateException", f"unexpected code: {code}"


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

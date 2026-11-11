"""start-participant-replication-source-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "start-participant-replication-source-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartParticipantReplication for a participant not publishing on the source stage fails ConflictException
    with the exact message and creates no replica; both stages stay readable."""
    ivsrt = ctx.client("ivs-realtime")
    source = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-src-"), tags={"env": "sim2real"}
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=source["arn"]))
    destination = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-dst-"), tags={"env": "sim2real"}
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=destination["arn"]))

    error = _client_error(
        lambda: ivsrt.start_participant_replication(
            sourceStageArn=source["arn"],
            destinationStageArn=destination["arn"],
            participantId="no-such-participant",
        )
    )
    assert error["Code"] == "ConflictException", f"expected ConflictException, got {error!r}"
    assert error["Message"] == "no-such-participant is not publishing", (
        f"unexpected StartParticipantReplication conflict message: {error['Message']!r}"
    )

    # Effect absent: no replicas exist for this (nonexistent) participant.
    replicas = ivsrt.list_participant_replicas(
        sourceStageArn=source["arn"], participantId="no-such-participant"
    )["replicas"]
    assert replicas == [], f"expected no replicas, got {replicas!r}"

    # Positive control: both stages remain fully reachable and functional.
    got_source = ivsrt.get_stage(arn=source["arn"])["stage"]["arn"]
    assert got_source == source["arn"], f"expected {source['arn']!r}, got {got_source!r}"
    got_dest = ivsrt.get_stage(arn=destination["arn"])["stage"]["arn"]
    assert got_dest == destination["arn"], f"expected {destination['arn']!r}, got {got_dest!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

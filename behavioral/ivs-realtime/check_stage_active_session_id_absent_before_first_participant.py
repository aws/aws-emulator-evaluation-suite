"""stage-active-session-id-absent-before-first-participant."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-active-session-id-absent-before-first-participant"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stage's ActiveSessionId is absent until a session actually starts. A newly
    created stage that nobody has published to must not report an ActiveSessionId,
    and ListStageSessions for it must be empty."""
    client = ctx.client("ivs-realtime")
    stage = client.create_stage(
        name=ctx.unique_name("sim2real-stage"), tags={"sim2real:managed": "true"}
    )["stage"]
    stage_arn = stage["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    assert not stage.get("activeSessionId"), f"CreateStage reported an activeSessionId on a stage nobody published to: {stage}"

    fetched = client.get_stage(arn=stage_arn)["stage"]
    assert fetched["arn"] == stage_arn, f"GetStage returned a different stage: expected {stage_arn}, got {fetched['arn']}"
    assert not fetched.get("activeSessionId"), f"GetStage reported an activeSessionId on a stage nobody published to: {fetched}"

    sessions = client.list_stage_sessions(stageArn=stage_arn)["stageSessions"]
    assert sessions == [], f"ListStageSessions returned sessions for a stage nobody published to: {sessions}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

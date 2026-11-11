"""create-stage-participant-token-configuration-attributes-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stage-participant-token-configuration-attributes-roundtrip"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStage's participantTokenConfigurations[].attributes are encoded into the
    corresponding minted ParticipantToken, matched by userId -- not dropped or merged
    across configurations."""
    ivsrt = ctx.client("ivs-realtime")
    configs = [
        {"userId": "host-1", "attributes": {"role": "host", "team": "red"}},
        {"userId": "guest-1", "attributes": {"role": "guest"}},
    ]
    resp = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"),
        participantTokenConfigurations=configs,
        tags={"env": "sim2real"},
    )
    stage = resp["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    by_user = {t["userId"]: t for t in resp["participantTokens"]}
    assert by_user["host-1"]["attributes"] == {"role": "host", "team": "red"}, (
        f"host-1 attributes must match its own configuration exactly, got {by_user['host-1']['attributes']!r}"
    )
    assert by_user["guest-1"]["attributes"] == {"role": "guest"}, (
        f"guest-1 attributes must not inherit host-1's 'team' key or any other cross-configuration "
        f"leakage, got {by_user['guest-1']['attributes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

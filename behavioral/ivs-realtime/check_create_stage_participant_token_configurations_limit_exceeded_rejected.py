"""create-stage-participant-token-configurations-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stage-participant-token-configurations-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStage rejects more than 12 participantTokenConfigurations, while exactly 12
    succeeds and the rejected attempt creates nothing."""
    ivsrt = ctx.client("ivs-realtime")

    def _configs(n):
        return [{"userId": f"user-{i}"} for i in range(n)]

    stage = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"),
        participantTokenConfigurations=_configs(12),
        tags={"sim2real": "audit"},
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    rejected_name = ctx.unique_name("sim2real-ivsrt-stage-")
    error = _client_error(
        lambda: ivsrt.create_stage(
            name=rejected_name,
            participantTokenConfigurations=_configs(13),
            tags={"sim2real": "audit"},
        )
    )
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == (
        "CreateStage.participantTokenConfigurations is required to have a maximum length of 12, "
        "found 13"
    ), error

    # Effect absent: the rejected call created no stage under its name.
    names = {s["name"] for s in ivsrt.list_stages()["stages"]}
    assert rejected_name not in names, names

    # Independent terminal read at the destination: the earlier, valid stage is untouched.
    assert ivsrt.get_stage(arn=stage["arn"])["stage"]["arn"] == stage["arn"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

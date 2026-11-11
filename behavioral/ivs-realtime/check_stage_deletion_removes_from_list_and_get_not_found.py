"""stage-deletion-removes-from-list-and-get-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stage-deletion-removes-from-list-and-get-not-found"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteStage removes the stage from ListStages, and GetStage and a second DeleteStage on it then fail
    ResourceNotFoundException with the exact message."""
    client = ctx.client("ivs-realtime")
    arn = client.create_stage(name=ctx.unique_name("sim2real-stage"))["stage"]["arn"]
    state = {"deleted": False}
    ctx.on_cleanup(lambda: state["deleted"] or client.delete_stage(arn=arn))

    live_arns = _list_stage_arns(client)
    assert arn in live_arns, f"expected {arn} in ListStages right after creation, got {live_arns}"

    client.delete_stage(arn=arn)
    state["deleted"] = True

    remaining_arns = _list_stage_arns(client)
    assert arn not in remaining_arns, (
        f"expected {arn} absent from ListStages after delete, still present in {remaining_arns}"
    )

    get_code, get_message = _error(lambda: client.get_stage(arn=arn))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetStage on a deleted stage, got {get_code}"
    )
    assert get_message == f"Resource: {arn} not found", get_message

    delete_code, delete_message = _error(lambda: client.delete_stage(arn=arn))
    assert delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting an already-deleted stage, got {delete_code}"
    )
    assert delete_message == f"Resource: {arn} not found", delete_message


def _list_stage_arns(client) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        params = {"nextToken": next_token} if next_token else {}
        resp = client.list_stages(**params)
        arns.update(s["arn"] for s in resp["stages"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

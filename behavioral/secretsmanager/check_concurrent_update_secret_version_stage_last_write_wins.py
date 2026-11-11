"""concurrent-update-secret-version-stage-last-write-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-secret-version-stage-last-write-wins"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two racing opposite-direction UpdateSecretVersionStage moves of AWSCURRENT leave exactly one
    holder; a later move naming the non-holder as RemoveFromVersionId is rejected with
    InvalidParameterException and the holder is unchanged."""
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-stagerace-")
    secret = sm.create_secret(
        Name=secret_name,
        SecretString="version-1",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    v1 = secret["VersionId"]

    put = sm.put_secret_value(SecretId=secret_arn, SecretString="version-2")
    v2 = put["VersionId"]
    assert v1 != v2, f"put_secret_value returned the same VersionId as create_secret: {v1}"

    versions_before = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    stage_map_before = {v["VersionId"]: set(v.get("VersionStages", [])) for v in versions_before}
    assert "AWSCURRENT" in stage_map_before[v2], (
        f"expected v2={v2} to hold AWSCURRENT before the race, stages={stage_map_before[v2]}"
    )
    assert "AWSCURRENT" not in stage_map_before[v1], (
        f"expected v1={v1} to not hold AWSCURRENT before the race, stages={stage_map_before[v1]}"
    )

    def move_to(target_version_id, remove_from_version_id):
        try:
            sm.update_secret_version_stage(
                SecretId=secret_arn,
                VersionStage="AWSCURRENT",
                MoveToVersionId=target_version_id,
                RemoveFromVersionId=remove_from_version_id,
            )
            return "ok"
        except ClientError as err:
            if err.response["Error"]["Code"] in ("InvalidParameterException", "InvalidRequestException"):
                # RemoveFromVersionId no longer matched the actual AWSCURRENT holder
                # by the time this racer executed server-side -- it lost the race. The API
                # documents both 400 codes for a move whose RemoveFromVersionId does not match.
                return "lost"
            raise

    # Opposite-direction moves: (v2->v1) and (v1->v2). Whichever one actually finds
    # its RemoveFromVersionId still valid when the server processes it wins; the
    # other either is rejected outright, or (if it runs after the first has already
    # made its RemoveFromVersionId valid) becomes the final, later write.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(move_to, v1, v2),
            pool.submit(move_to, v2, v1),
        ]
        results = [f.result() for f in futures]

    assert "ok" in results, f"expected at least one racer to win the swap, got {results}"

    versions_after = sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
    current_holders = [v["VersionId"] for v in versions_after if "AWSCURRENT" in v.get("VersionStages", [])]
    assert len(current_holders) == 1, f"expected exactly one AWSCURRENT holder, got {current_holders}"
    winner = current_holders[0]
    assert winner in (v1, v2), f"AWSCURRENT landed on an unrelated version: {winner}"

    winning_content = {v1: "version-1", v2: "version-2"}[winner]
    fetched = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")
    assert fetched["VersionId"] == winner, (
        f"get_secret_value VersionStage=AWSCURRENT returned {fetched['VersionId']}, expected the "
        f"list-derived winner {winner}"
    )
    assert fetched["SecretString"] == winning_content, (
        f"AWSCURRENT content {fetched['SecretString']!r} disagrees with its winning version {winner}, "
        f"expected {winning_content!r}"
    )

    # Grade the stale-RemoveFromVersionId rejection on every run, whichever way the race resolved:
    # naming the non-holder as RemoveFromVersionId while the winner holds AWSCURRENT is refused.
    loser = v2 if winner == v1 else v1
    try:
        sm.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=loser,
            RemoveFromVersionId=loser,
        )
    except ClientError as err:
        stale_code = err.response["Error"]["Code"]
        stale_message = err.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"a move of AWSCURRENT to {loser} with stale RemoveFromVersionId={loser} while {winner} "
            "holds it must be rejected, but it succeeded"
        )
    assert stale_code == "InvalidParameterException", (
        f"a move of AWSCURRENT to {loser} with stale RemoveFromVersionId={loser} while {winner} holds "
        f"it must be rejected with InvalidParameterException, got {stale_code!r}"
    )
    expected_message = (
        "When you move staging label AWSCURRENT, if you specify RemoveFromVersionId, it must be set "
        f"to the version that currently has the staging label {winner}."
    )
    assert stale_message == expected_message, (
        f"unexpected stale-RemoveFromVersionId rejection message: {stale_message!r}"
    )
    still = [
        v["VersionId"]
        for v in sm.list_secret_version_ids(SecretId=secret_arn)["Versions"]
        if "AWSCURRENT" in v.get("VersionStages", [])
    ]
    assert still == [winner], f"the rejected stale move changed the AWSCURRENT holder: {still}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

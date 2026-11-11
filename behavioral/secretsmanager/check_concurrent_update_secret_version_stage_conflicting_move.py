"""concurrent-update-secret-version-stage-conflicting-move."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-secret-version-stage-conflicting-move"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent UpdateSecretVersionStage calls moving AWSCURRENT to different target
    versions resolve deterministically with exactly one label owner, no dual-current state."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-stagemove-")

    sm.create_secret(
        Name=name,
        SecretString="seed",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    version_x = sm.put_secret_value(SecretId=name, SecretString="candidate-x")["VersionId"]
    version_y = sm.put_secret_value(SecretId=name, SecretString="candidate-y")["VersionId"]
    version_z = sm.put_secret_value(SecretId=name, SecretString="candidate-z")["VersionId"]
    # after the three puts above, version_z is AWSCURRENT and version_y is AWSPREVIOUS; version_x
    # holds no staging label. Both racers try to move AWSCURRENT *away from* version_z (the label's
    # current owner) -- per the API contract, RemoveFromVersionId must match whoever currently
    # holds the label or the call fails, so at most one of these two same-source moves can win.
    values_by_version = {version_x: "candidate-x", version_y: "candidate-y", version_z: "candidate-z"}

    def move_to_x():
        return sm.update_secret_version_stage(
            SecretId=name,
            VersionStage="AWSCURRENT",
            MoveToVersionId=version_x,
            RemoveFromVersionId=version_z,
        )

    def move_to_y():
        return sm.update_secret_version_stage(
            SecretId=name,
            VersionStage="AWSCURRENT",
            MoveToVersionId=version_y,
            RemoveFromVersionId=version_z,
        )

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(move_to_x), pool.submit(move_to_y)]
        for fut in futures:
            try:
                fut.result()
                results.append("ok")
            except Exception as exc:  # noqa: BLE001 - a losing racer may legitimately error
                if hasattr(exc, "response"):
                    error = exc.response.get("Error", {})
                    results.append((error.get("Code", type(exc).__name__), error.get("Message")))
                else:
                    results.append((type(exc).__name__, None))

    assert "ok" in results, f"codes: {results}"
    # A losing racer must fail with the stale-RemoveFromVersionId error AWS answers, not something
    # unrelated -- this is the "no dual-current, deterministic resolution" contract in action.
    for result in results:
        if result != "ok":
            assert result[0] == "InvalidParameterException", "loser_code:" + result[0]

    ids = sm.list_secret_version_ids(SecretId=name, IncludeDeprecated=True)["Versions"]
    current_owners = [v["VersionId"] for v in ids if "AWSCURRENT" in v.get("VersionStages", [])]
    assert len(current_owners) == 1, f"expected exactly one AWSCURRENT owner, got {current_owners}"
    assert current_owners[0] in (version_x, version_y), "AWSCURRENT landed on an unrelated version"

    winner = current_owners[0]
    got = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
    assert got["SecretString"] == values_by_version[winner], (
        "AWSCURRENT content disagrees with its version id"
    )
    assert got["VersionId"] == winner, (
        f"get_secret_value VersionStage=AWSCURRENT returned VersionId={got['VersionId']!r}, "
        f"expected the list-derived winner {winner!r}"
    )
    # The losing racer's message names the version that holds AWSCURRENT, so it is checked here.
    expected = (
        "When you move staging label AWSCURRENT, if you specify RemoveFromVersionId, it must be set "
        f"to the version that currently has the staging label {winner}."
    )
    for result in results:
        if result != "ok":
            assert result[1] == expected, f"expected {expected!r}, got {result[1]!r}"



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

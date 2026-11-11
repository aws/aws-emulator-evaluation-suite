"""put-secret-value-version-stages-list-moves-every-label-in-one-call."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-secret-value-version-stages-list-moves-every-label-in-one-call"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """One PutSecretValue with VersionStages=[AWSCURRENT, AWSPENDING] moves both labels from two
    different versions onto the new one; the old current demotes to AWSPREVIOUS and a custom
    label on the old pending version stays put.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-smmultistage-")
    created = sm.create_secret(
        Name=name,
        SecretString="v1",
        Tags=[
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    v2 = sm.put_secret_value(
        SecretId=arn, SecretString="v2", VersionStages=["AWSPENDING", "MYSTAGE"]
    )["VersionId"]
    assert v2 != v1, "PutSecretValue must mint a new version id"

    stages = _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        lambda m: set(m.get(v2, [])) == {"AWSPENDING", "MYSTAGE"},
        timeout_s=60.0,
        interval_s=2.0,
        description="both labels to settle on v2",
    )
    assert set(stages.get(v2, [])) == {"AWSPENDING", "MYSTAGE"}, (
        f"v2 ({v2}) must carry both AWSPENDING and MYSTAGE, got {stages.get(v2)!r}"
    )
    assert stages.get(v1) == ["AWSCURRENT"], (
        f"AWSCURRENT must remain on v1 ({v1}) untouched, got {stages.get(v1)!r}"
    )

    # One call names two labels that currently sit on two DIFFERENT versions (AWSCURRENT on v1,
    # AWSPENDING on v2) and must relocate both onto v3 in the same request.
    v3 = sm.put_secret_value(
        SecretId=arn, SecretString="v3", VersionStages=["AWSCURRENT", "AWSPENDING"]
    )["VersionId"]
    assert v3 not in (v1, v2), f"PutSecretValue must mint a version id distinct from both, got {v3}"

    after = _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        lambda m: set(m.get(v3, [])) == {"AWSCURRENT", "AWSPENDING"},
        timeout_s=60.0,
        interval_s=2.0,
        description="both relocated labels to settle on v3",
    )
    assert set(after.get(v3, [])) == {"AWSCURRENT", "AWSPENDING"}, (
        f"v3 ({v3}) must carry both AWSCURRENT (moved from v1) and AWSPENDING (moved from v2) in "
        f"the same call, got {after.get(v3)!r}"
    )
    assert after.get(v1) == ["AWSPREVIOUS"], (
        f"v1 ({v1}) must demote to exactly ['AWSPREVIOUS'] once AWSCURRENT moves off it, got "
        f"{after.get(v1)!r}"
    )
    # Only AWSPENDING is implicitly evicted; a caller-defined label moves only when named.
    assert after.get(v2) == ["MYSTAGE"], (
        f"v2 ({v2}) lost AWSPENDING because the second call relocated it, but its un-named "
        f"MYSTAGE label must be left exactly where it was -- custom labels are never implicitly "
        f"evicted; expected ['MYSTAGE'], got {after.get(v2)!r}"
    )

    current = sm.get_secret_value(SecretId=arn)
    assert current["VersionId"] == v3 and current["SecretString"] == "v3", (
        f"a default read must resolve the new AWSCURRENT v3 with bytes 'v3', got version "
        f"{current.get('VersionId')!r} value {current.get('SecretString')!r}"
    )
    by_pending = sm.get_secret_value(SecretId=arn, VersionStage="AWSPENDING")
    assert by_pending["VersionId"] == v3 and by_pending["SecretString"] == "v3", (
        f"VersionStage=AWSPENDING must now resolve the relocated v3 with bytes 'v3', got version "
        f"{by_pending.get('VersionId')!r} value {by_pending.get('SecretString')!r}"
    )
    by_custom = sm.get_secret_value(SecretId=arn, VersionStage="MYSTAGE")
    assert by_custom["VersionId"] == v2 and by_custom["SecretString"] == "v2", (
        f"VersionStage=MYSTAGE must still resolve v2 with its original bytes 'v2', got version "
        f"{by_custom.get('VersionId')!r} value {by_custom.get('SecretString')!r}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout, never returning its last observation silently."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

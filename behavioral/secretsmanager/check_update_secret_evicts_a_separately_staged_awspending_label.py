"""update-secret-evicts-a-separately-staged-awspending-label."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-secret-evicts-a-separately-staged-awspending-label"
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
    """UpdateSecret moves AWSCURRENT to its new version, demotes the old one to AWSPREVIOUS, and
    evicts AWSPENDING from a separately staged version, whose bytes stay readable by VersionId.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-smupdpend-")
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
        SecretId=arn, SecretString="pending-v2", VersionStages=["AWSPENDING"]
    )["VersionId"]
    assert v2 != v1, "PutSecretValue must mint a new version id"

    staged = _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        lambda m: "AWSPENDING" in m.get(v2, []),
        timeout_s=60.0,
        interval_s=2.0,
        description="AWSPENDING to settle on v2",
    )
    assert staged.get(v1) == ["AWSCURRENT"], (
        f"expected v1 ({v1}) to still hold exactly ['AWSCURRENT'], got {staged.get(v1)!r}"
    )
    assert staged.get(v2) == ["AWSPENDING"], (
        f"expected v2 ({v2}) to hold exactly ['AWSPENDING'], got {staged.get(v2)!r}"
    )

    updated = sm.update_secret(SecretId=name, SecretString="v3")
    v3 = updated["VersionId"]
    assert v3 not in (v1, v2), (
        f"UpdateSecret must mint a version id distinct from both existing ones, got {v3}"
    )

    after = _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        lambda m: "AWSCURRENT" in m.get(v3, []),
        timeout_s=60.0,
        interval_s=2.0,
        description="AWSCURRENT to move to v3",
    )
    assert after.get(v3) == ["AWSCURRENT"], (
        f"expected the new version v3 ({v3}) to hold exactly ['AWSCURRENT'], got {after.get(v3)!r}"
    )
    assert after.get(v1) == ["AWSPREVIOUS"], (
        f"expected the prior AWSCURRENT v1 ({v1}) to demote to exactly ['AWSPREVIOUS'], got "
        f"{after.get(v1)!r}"
    )
    assert v2 not in after, (
        f"UpdateSecret must EVICT the separately-staged AWSPENDING version v2 ({v2}) from the "
        f"staging index entirely; expected no entry, got {after.get(v2)!r}"
    )

    # Minting a new AWSCURRENT without re-naming AWSPENDING cancels the stale pending version.
    evicted = sm.get_secret_value(SecretId=arn, VersionId=v2)
    assert evicted["SecretString"] == "pending-v2", (
        f"evicting the AWSPENDING label must not delete v2's bytes, got "
        f"{evicted.get('SecretString')!r}"
    )
    assert "VersionStages" not in evicted, (
        f"an evicted version must echo no VersionStages at all, got {evicted.get('VersionStages')!r}"
    )

    code, message = _error_code(
        lambda: sm.get_secret_value(SecretId=arn, VersionStage="AWSPENDING")
    )
    assert code == "ResourceNotFoundException", (
        f"VersionStage=AWSPENDING must no longer resolve anything after the eviction, got {code!r}"
    )
    assert message == (
        "Secrets Manager can't find the specified secret value for staging label: AWSPENDING"
    ), f"unexpected not-found message: {message!r}"

    current_read = sm.get_secret_value(SecretId=arn)
    assert current_read["VersionId"] == v3, (
        f"a default read must resolve the new AWSCURRENT v3 ({v3}), got "
        f"{current_read.get('VersionId')!r}"
    )
    assert current_read["SecretString"] == "v3", (
        f"a default read must serve UpdateSecret's new value, got {current_read.get('SecretString')!r}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll that raises on timeout."""
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


def _error_code(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""get-secret-value-rejects-a-version-id-and-version-stage-that-disagree."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_DISAGREE_MESSAGE = "You provided a VersionStage that is not associated to the provided VersionId."
CHECK = "get-secret-value-rejects-a-version-id-and-version-stage-that-disagree"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetSecretValue refuses a (VersionId, VersionStage) pair that names two different versions,
    and accepts the identical request once the two agree — in both directions.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    """
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-smdisagree-")
    created = sm.create_secret(
        Name=name,
        SecretString="value-v1",
        Description="sim2real behavioral draft: VersionId/VersionStage disagreement",
        Tags=_sim2real_tags(),
    )
    arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    v2 = sm.put_secret_value(SecretId=arn, SecretString="value-v2")["VersionId"]
    assert v2 != v1, f"PutSecretValue must mint a new version id; got {v2!r} == {v1!r}"

    # The staging index settles asynchronously, so poll before asserting on it. The poll waits only
    # for v1 to stop showing as current, so the exact-set assertions below can still fail.
    stages = _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        lambda m: v1 in m and v2 in m and "AWSCURRENT" not in m.get(v1, []),
        timeout_s=60.0,
        interval_s=2.0,
        description="the staging index to stop reporting v1 as AWSCURRENT after the v2 write",
    )
    assert stages[v2] == ["AWSCURRENT"], (
        f"expected v2 ({v2}) to hold exactly ['AWSCURRENT']; DescribeSecret reported "
        f"{stages.get(v2)!r} (full map {stages!r})"
    )
    assert stages[v1] == ["AWSPREVIOUS"], (
        f"expected v1 ({v1}) to hold exactly ['AWSPREVIOUS']; DescribeSecret reported "
        f"{stages.get(v1)!r} (full map {stages!r})"
    )

    # --- Beat 1: positive control. Both AGREEING pairs are accepted and serve the right bytes. ---
    agree_current = sm.get_secret_value(SecretId=arn, VersionId=v2, VersionStage="AWSCURRENT")
    assert agree_current["SecretString"] == "value-v2", (
        f"an agreeing (VersionId=v2, VersionStage=AWSCURRENT) pair must serve v2's bytes; expected "
        f"'value-v2', got {agree_current.get('SecretString')!r}"
    )
    agree_previous = sm.get_secret_value(SecretId=arn, VersionId=v1, VersionStage="AWSPREVIOUS")
    assert agree_previous["SecretString"] == "value-v1", (
        f"an agreeing (VersionId=v1, VersionStage=AWSPREVIOUS) pair must serve v1's bytes; expected "
        f"'value-v1', got {agree_previous.get('SecretString')!r}"
    )

    # --- Beat 2/3: break exactly one thing -- the stage -- and demand a specific refusal. ---
    # Direction A: the id names the demoted version, the stage names the current one.
    code_a, message_a = _error_code(
        lambda: sm.get_secret_value(SecretId=arn, VersionId=v1, VersionStage="AWSCURRENT")
    )
    assert code_a == "InvalidRequestException", (
        f"GetSecretValue(VersionId=v1={v1}, VersionStage='AWSCURRENT') names two different "
        f"versions and must be refused with InvalidRequestException; got {code_a!r}"
    )
    assert message_a == _DISAGREE_MESSAGE, f"unexpected refusal message: {message_a!r}"

    # Direction B: the mirror image, so a target cannot pass by rejecting only one ordering.
    code_b, message_b = _error_code(
        lambda: sm.get_secret_value(SecretId=arn, VersionId=v2, VersionStage="AWSPREVIOUS")
    )
    assert code_b == "InvalidRequestException", (
        f"GetSecretValue(VersionId=v2={v2}, VersionStage='AWSPREVIOUS') names two different "
        f"versions and must be refused with InvalidRequestException; got {code_b!r}"
    )
    assert message_b == _DISAGREE_MESSAGE, f"unexpected refusal message: {message_b!r}"
    assert code_a == code_b, (
        f"both disagreement directions must be classified identically; the id-is-older direction "
        f"returned {code_a!r} and the stage-is-older direction returned {code_b!r}"
    )

    # --- Beat 4: effect absent. Nothing about the secret moved because of the refusals. ---
    after = sm.describe_secret(SecretId=arn)["VersionIdsToStages"]
    assert after == stages, (
        f"a refused GetSecretValue must not touch the staging index; before {stages!r}, "
        f"after {after!r}"
    )

    # --- Beat 5/6: restore -- correct the single broken parameter and demand the identical call. ---
    restored = sm.get_secret_value(SecretId=arn, VersionId=v1, VersionStage="AWSPREVIOUS")
    assert restored["SecretString"] == "value-v1", (
        f"correcting only the stage on the refused request must make it succeed and serve v1's "
        f"bytes; expected 'value-v1', got {restored.get('SecretString')!r}"
    )
    assert restored["VersionId"] == v1, (
        f"the restored read must resolve to v1 ({v1}); got {restored.get('VersionId')!r}"
    )
    assert restored["VersionStages"] == ["AWSPREVIOUS"], (
        f"the restored read's echoed staging labels must be exactly ['AWSPREVIOUS']; got "
        f"{restored.get('VersionStages')!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _error_code(fn):
    """The captured AWS (error code, message). An unexpected success raises, so accepting input AWS
    refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout, never returning its last observation."""
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

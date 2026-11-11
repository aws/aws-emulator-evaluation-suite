"""configuration-set-client-token-idempotency-holds-under-concurrent-create."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-set-client-token-idempotency-holds-under-concurrent-create"
GROUP = "configuration-sets"
SERVICES = ["pinpoint-sms-voice-v2"]

_WORKERS = 5


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_with_retry(c, name: str, token: str):
    """('ok', arn) on success, ('conflict', (code, message)) on a documented conflict loser."""
    deadline = time.monotonic() + 30
    while True:
        try:
            r = c.create_configuration_set(ConfigurationSetName=name, ClientToken=token)
            return "ok", r["ConfigurationSetArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ThrottlingException" and time.monotonic() < deadline:
                time.sleep(0.5)
                continue
            return "conflict", (code, message)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Racing identical creates under one client token leaves exactly one configuration
    set behind: every racer either gets that set's ARN or the documented conflict, never
    a second resource or an unrelated error.
    """
    c = ctx.client("pinpoint-sms-voice-v2")
    name = ctx.unique_name("sim2real-behav-pinpoint-tokrace-")
    token = ctx.unique_name("sim2real-behav-pinpoint-token-")
    ctx.on_cleanup(
        _teardown(
            lambda: c.delete_configuration_set(ConfigurationSetName=name),
            "ResourceNotFoundException",
        )
    )

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        results = list(pool.map(lambda _: _create_with_retry(c, name, token), range(_WORKERS)))

    oks = [arn for outcome, arn in results if outcome == "ok"]
    conflicts = [detail for outcome, detail in results if outcome == "conflict"]
    assert oks, f"no racer succeeded; every attempt was refused: {results!r}"
    assert len(set(oks)) == 1, f"racers that succeeded disagree on the ARN: {sorted(set(oks))!r}"
    expected_conflict = (
        "ConflictException",
        f'Conflict Occurred - Reason="RESOURCE_ALREADY_EXISTS" '
        f'ResourceType="configuration-set" ResourceId="{name}"',
    )
    assert all(detail == expected_conflict for detail in conflicts), (
        f"a racer's refusal was {[d for d in conflicts if d != expected_conflict]!r}, "
        f"expected only the exact documented conflict {expected_conflict!r}"
    )

    described = c.describe_configuration_sets(ConfigurationSetNames=[name])["ConfigurationSets"]
    assert len(described) == 1, (
        f"expected exactly one configuration set named {name!r}, found {described!r}"
    )
    assert described[0]["ConfigurationSetArn"] == oks[0], (
        f"the surviving set's ARN {described[0]['ConfigurationSetArn']!r} does not match "
        f"what the racers that succeeded returned {oks[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

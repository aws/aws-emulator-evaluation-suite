"""create-action-target-concurrent-race-exactly-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-action-target-concurrent-race-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["securityhub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """N concurrent CreateActionTarget calls for the same Id: exactly one wins, the rest get ResourceConflictException."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    action_id = _action_id(ctx)

    def _attempt(i):
        try:
            resp = sh.create_action_target(
                Name=f"sim2real-race-{i}", Description="sim2real behavioral concurrency test", Id=action_id
            )
            return ("ok", resp["ActionTargetArn"])
        except Exception as exc:  # noqa: BLE001 - classify below
            error = getattr(exc, "response", {}).get("Error", {})
            return ("err", error.get("Code"), error.get("Message"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_attempt, range(8)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly one winner, got {successes}"
    assert len(failures) == 7, f"expected exactly seven losers, got {failures}"
    assert all(code == "ResourceConflictException" for _, code, _ in failures), failures
    expected = f"Action with Id: {action_id} already exists"
    assert all(message == expected for _, _, message in failures), (expected, failures)

    arn = successes[0][1]
    ctx.on_cleanup(lambda: sh.delete_action_target(ActionTargetArn=arn))

    listed = sh.describe_action_targets(ActionTargetArns=[arn])["ActionTargets"]
    assert len(listed) == 1, f"expected the winning action target {arn} to be independently describable, got {listed}"


def _action_id(ctx):
    raw = ctx.unique_name("sim2real")
    alnum = "".join(c for c in raw if c.isalnum())
    return alnum[:20]


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

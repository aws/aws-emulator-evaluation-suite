"""concurrent-register-pull-time-update-exclusion-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-register-pull-time-update-exclusion-race"
GROUP = "concurrency"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """N concurrent RegisterPullTimeUpdateExclusion calls for the identical principal resolve
    to exactly one stored entry; every losing racer receives ExclusionAlreadyExistsException,
    never a silent success or a different error."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    principal = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ecr-race-')}"
    ctx.on_cleanup(lambda: _deregister(ecr, principal))

    racer_count = 6

    def _racer(_i):
        try:
            ecr.register_pull_time_update_exclusion(principalArn=principal)
            return ("ok", None, None)
        except Exception as exc:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            raise

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    assert all(code == "ExclusionAlreadyExistsException" for _, code, _ in failures), (
        f"expected every loser to get ExclusionAlreadyExistsException, got codes: "
        f"{[code for _, code, _ in failures]}"
    )
    expected = (
        f"The pull time update exclusion for principal arn '{principal}' already exists "
        f"in registry with id '{account_id}'"
    )
    for _, _, message in failures:
        assert message == expected, f"expected every loser's message to be {expected!r}, got {message!r}"

    entries = [
        e
        for e in ecr.list_pull_time_update_exclusions()["pullTimeUpdateExclusions"]
        if e == principal
    ]
    assert len(entries) == 1, (
        f"expected exactly 1 stored exclusion entry for {principal}, got {len(entries)}"
    )


def _deregister(ecr, principal_arn):
    from botocore.exceptions import ClientError

    try:
        ecr.deregister_pull_time_update_exclusion(principalArn=principal_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExclusionNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

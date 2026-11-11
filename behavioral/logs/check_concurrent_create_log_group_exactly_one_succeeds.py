"""concurrent-create-log-group-exactly-one-succeeds."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-log-group-exactly-one-succeeds"
GROUP = 'concurrency'
SERVICES = ['logs']

def _run_concurrent(fns) -> list:
    """Invoke zero-arg callables concurrently; one outcome record per callable, in order."""

    def _wrap(fn):
        try:
            return {"ok": True, "value": fn(), "error_code": None}
        except ClientError as exc:
            return {
                "ok": False,
                "value": None,
                "error_code": exc.response.get("Error", {}).get("Code"),
                "error_message": exc.response.get("Error", {}).get("Message"),
            }
        except Exception as exc:  # noqa: BLE001 - surface unexpected failures
            return {"ok": False, "value": None, "error_code": type(exc).__name__}

    with ThreadPoolExecutor(max_workers=max(2, len(fns))) as pool:
        return list(pool.map(_wrap, fns))


def _concurrent_successes(results) -> int:
    return sum(1 for r in results if r["ok"])


def _concurrent_error_codes(results) -> list:
    return [r["error_code"] for r in results if not r["ok"]]


def _create_log_group(ctx, logs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    return name


def _delete_log_group(logs, name) -> None:
    """Drop deletion protection (if any) before deleting, mirroring the suite's teardown."""
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=name, deletionProtectionEnabled=False
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs.delete_log_group(logGroupName=name)


def _describe_log_group(logs, name):
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    for g in resp.get("logGroups", []):
        if g["logGroupName"] == name:
            return g
    return None

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateLogGroup calls with the same name: exactly one succeeds, the rest get ResourceAlreadyExistsException."""
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-race-")
    # The winner's group is real state; register teardown BEFORE racing so it is
    # reclaimed no matter which racer won or where an assertion below fires.
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    n = 6

    def create():
        return logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})

    results = _run_concurrent([create] * n)
    n_success = _concurrent_successes(results)
    error_codes = [c for c in _concurrent_error_codes(results) if c is not None]

    assert n_success == 1, f"expected exactly 1 successful create, got {n_success}: {results}"
    assert len(error_codes) == n - 1, f"expected {n - 1} failures, got {len(error_codes)}"
    # Real AWS serialises concurrent creates: every loser sees the already-exists refusal.
    for r in results:
        if not r["ok"]:
            assert r["error_code"] == "ResourceAlreadyExistsException", f"unexpected loser outcome: {r!r}"
            assert r["error_message"] == "The specified log group already exists", (
                f"unexpected already-exists message: {r!r}"
            )
    group = _describe_log_group(logs, name)
    assert group is not None, f"expected {name} to be visible via an independent DescribeLogGroups read, got None"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

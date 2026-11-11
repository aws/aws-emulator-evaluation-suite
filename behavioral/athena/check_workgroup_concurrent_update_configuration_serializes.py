"""workgroup-concurrent-update-configuration-serializes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "workgroup-concurrent-update-configuration-serializes"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateWorkGroup calls are applied atomically: at least one racer succeeds (losers
    get InvalidRequestException) and GetWorkGroup then shows exactly one accepted description."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-wg-race-")
    athena.create_work_group(
        Name=wg,
        Description="initial",
        Tags=[{"Key": "sim2real", "Value": "workgroup-concurrent-update-race"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_wg(athena, wg))

    candidates = [f"racer-description-{i}" for i in range(5)]

    def _update(desc: str) -> tuple[str, bool, str | None, str | None]:
        try:
            athena.update_work_group(WorkGroup=wg, Description=desc)
            return desc, True, None, None
        except Exception as exc:  # noqa: BLE001 - capture code for assertion below
            from botocore.exceptions import ClientError

            if not isinstance(exc, ClientError):
                return desc, False, type(exc).__name__, str(exc)
            return desc, False, exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        results = list(pool.map(_update, candidates))

    accepted = [desc for desc, ok, _, _ in results if ok]
    rejected = [(desc, code, message) for desc, ok, code, message in results if not ok]
    # A workgroup can only be updated one write at a time: at least one racing writer must
    # be accepted, and any writer that loses the race must be rejected with a proper
    # conflict/invalid-request error -- never silently dropped or corrupted.
    assert len(accepted) >= 1, f"expected at least one update accepted, got {results}"
    expected_message = (
        "The WorkGroup was updated by another concurrent request while we were trying to "
        "update it. This might happen if you try to update the WorkGroup in quick successions."
    )
    for desc, code, message in rejected:
        assert code == "InvalidRequestException", (
            f"expected losing racer {desc!r} to be rejected with InvalidRequestException, "
            f"got {code} (all results: {results})"
        )
        assert message == expected_message, (
            f"expected losing racer {desc!r} to carry {expected_message!r}, got {message!r}"
        )

    final = athena.get_work_group(WorkGroup=wg)["WorkGroup"]
    assert final["Description"] in accepted, (
        f"final description {final['Description']!r} is not one of the accepted racing "
        f"writes {accepted!r} -- lost update or corruption"
    )
    assert final["Description"] != "initial"


def _safe_delete_wg(athena: Any, name: str) -> None:
    """Delete the workgroup; return only on Athena's not-found refusal, raise anything else."""
    from botocore.exceptions import ClientError

    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] != "InvalidRequestException" or "not found" not in error.get("Message", "").lower():
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

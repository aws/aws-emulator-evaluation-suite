"""limit-current-count-initial-zero."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "limit-current-count-initial-zero"
GROUP = "data-plane"
SERVICES = ["deadline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created limit reports currentCount 0 against the configured maxCount before
    any usage exists."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    display_name = ctx.unique_name("sim2real-limit-")
    limit_id = deadline.create_limit(
        farmId=farm_id,
        displayName=display_name,
        amountRequirementName="amount.Sim2realLimitTest",
        maxCount=7,
    )["limitId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_limit(farmId=farm_id, limitId=limit_id)))

    limit = deadline.get_limit(farmId=farm_id, limitId=limit_id)
    assert limit["displayName"] == display_name, f"expected displayName {display_name!r}, got {limit['displayName']!r}"
    assert limit["maxCount"] == 7, f"expected maxCount 7, got {limit['maxCount']}"
    assert limit["currentCount"] == 0, f"expected currentCount 0, got {limit['currentCount']}"

    limits = deadline.list_limits(farmId=farm_id)["limits"]
    listed = next((entry for entry in limits if entry["limitId"] == limit_id), None)
    assert listed is not None, f"limit {limit_id} not found in list_limits for farm {farm_id}"
    assert listed["currentCount"] == 0, f"expected currentCount 0 in list_limits, got {listed['currentCount']}"


# ===== helpers =====
def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(
                displayName=ctx.unique_name("sim2real-farm-"),
                tags={"sim2real-check": "limit-current-count-initial-zero"},
            )["farmId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _safe(fn) -> None:
    """Teardown: done on ResourceNotFoundException; retries ConflictException (a child still
    being released) every 2 s for up to 60 s; raises everything else."""
    from botocore.exceptions import ClientError

    deadline_t = time.monotonic() + 60.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline_t:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

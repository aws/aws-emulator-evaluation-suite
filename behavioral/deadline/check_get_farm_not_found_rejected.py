"""get-farm-not-found-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-farm-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFarm returns a created farm's farmId and displayName, and fails for a well-formed never-created farmId
    with ResourceNotFoundException and its exact message."""
    deadline = ctx.client("deadline")

    display_name = ctx.unique_name("sim2real-farm-")
    farm_id = _create_farm_with_retry(ctx, deadline, display_name, {"sim2real": "true"})
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    farm = deadline.get_farm(farmId=farm_id)
    assert farm["farmId"] == farm_id, f"expected farmId {farm_id}, got {farm['farmId']}"
    assert farm["displayName"] == display_name, (
        f"expected displayName {display_name}, got {farm['displayName']}"
    )

    bogus_farm_id = _perturb_farm_id(farm_id)
    assert bogus_farm_id != farm_id, f"perturbed id {bogus_farm_id} collided with real {farm_id}"
    error = _client_error(lambda: deadline.get_farm(farmId=bogus_farm_id))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error}"
    )
    expected_message = f"Resource of type farm with id {bogus_farm_id} does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _create_farm_with_retry(ctx, deadline, display_name, tags):
    from botocore.exceptions import ClientError

    last_exc = None
    budget = time.monotonic() + 180.0
    while time.monotonic() < budget:
        try:
            return deadline.create_farm(displayName=display_name, tags=tags)["farmId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _perturb_farm_id(farm_id: str) -> str:
    """Flip the last hex digit of a real farmId so the bogus probe stays syntactically valid
    (`^farm-[0-9a-f]{32}$`) and inside the same resource scope as the real one, rather than a
    fabricated id that could land outside the probe identity's grant and surface
    AccessDeniedException instead of the not-found semantics under test."""
    last = farm_id[-1]
    flipped = "1" if last == "0" else "0"
    return farm_id[:-1] + flipped


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

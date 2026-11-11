"""queue-environment-create-get-semantics."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "queue-environment-create-get-semantics"
GROUP = "data-plane"
SERVICES = ["deadline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQueueEnvironment persists the exact priority, templateType and template body,
    round-tripped through GetQueueEnvironment. DeleteQueueEnvironment then removes it: an
    independent GetQueueEnvironment on the dead id is rejected with ResourceNotFoundException."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-queue-"),
        tags={"sim2real": "behavioral"},
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    template = json.dumps(
        {
            "specificationVersion": "environment-2023-09",
            "environment": {
                "name": "SimpleEnv",
                "variables": {"SIM2REAL_TEST_VAR": "offscreen"},
            },
        }
    )

    env_id = deadline.create_queue_environment(
        farmId=farm_id,
        queueId=queue_id,
        priority=5,
        templateType="JSON",
        template=template,
    )["queueEnvironmentId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: deadline.delete_queue_environment(
                farmId=farm_id, queueId=queue_id, queueEnvironmentId=env_id
            )
        )
    )

    env = deadline.get_queue_environment(farmId=farm_id, queueId=queue_id, queueEnvironmentId=env_id)
    assert env["priority"] == 5, f"expected priority 5 to persist as submitted, got {env['priority']}"
    assert env["templateType"] == "JSON", f"expected templateType JSON to persist, got {env['templateType']}"
    got_template = json.loads(env["template"])
    want_template = json.loads(template)
    assert got_template == want_template, f"expected template body {want_template!r}, got {got_template!r}"

    deadline.delete_queue_environment(farmId=farm_id, queueId=queue_id, queueEnvironmentId=env_id)
    error = _client_error(
        lambda: deadline.get_queue_environment(
            farmId=farm_id, queueId=queue_id, queueEnvironmentId=env_id
        )
    )
    assert error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error}"
    assert error.get("Message") == (
        f"Resource of type queue-env with id '{queue_id}' / '{env_id}' does not exist."
    ), (
        f"expected the exact ResourceNotFoundException message, got {error.get('Message')!r}"
    )


# ===== helpers =====
def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(
                displayName=ctx.unique_name("sim2real-farm-"), tags={"sim2real": "behavioral"}
            )["farmId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not be reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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

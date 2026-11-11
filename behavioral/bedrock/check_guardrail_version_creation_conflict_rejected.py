"""guardrail-version-creation-conflict-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "guardrail-version-creation-conflict-rejected"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two concurrent CreateGuardrailVersion calls, a loser gets ValidationException saying the
    guardrail can't be modified at this time and two winners get distinct, readable versions; once
    the guardrail is READY again a further version is created and readable."""
    bedrock = ctx.client("bedrock")
    guardrail = _create_guardrail(ctx, bedrock)

    def _create_version() -> dict[str, Any]:
        return bedrock.create_guardrail_version(guardrailIdentifier=guardrail["id"])

    successes: list[dict[str, Any]] = []
    failures: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create_version) for _ in range(2)]
        for future in futures:
            try:
                successes.append(future.result())
            except Exception as exc:  # noqa: BLE001 - reraised via _error_code below
                code = _client_error_code(exc)
                if code is None:
                    raise
                failures.append((code, exc.response["Error"].get("Message", "")))

    assert len(successes) + len(failures) == 2, (successes, failures)
    # Whichever racer(s) fail must fail with exactly ValidationException naming
    # the guardrail as not modifiable right now -- never a different/undocumented
    # error code, and never a validation failure for an unrelated reason.
    assert all(code == "ValidationException" for code, _ in failures), failures
    assert all("can't be modified at this time" in msg for _, msg in failures), failures
    if len(successes) == 2:
        # Real AWS may serialize both requests rather than reject the loser;
        # that's fine, but the two accepted versions must be distinct, and each
        # must be independently retrievable through GetGuardrail -- not just
        # echoed back by the mutating CreateGuardrailVersion response itself.
        versions = [s["version"] for s in successes]
        assert len(set(versions)) == 2, (
            f"both concurrent CreateGuardrailVersion calls succeeded but returned "
            f"the same version number: {versions}"
        )
        for version in versions:
            fetched = bedrock.get_guardrail(guardrailIdentifier=guardrail["id"], guardrailVersion=version)
            assert fetched["version"] == version, (
                f"GetGuardrail for version {version} returned {fetched.get('version')!r}"
            )
    else:
        assert len(successes) == 1, f"expected exactly one winning racer, got {len(successes)}"

    # Positive control: after the guardrail settles, version creation succeeds
    # again, and the new version is independently readable through GetGuardrail
    # -- a different operation than the one that created it.
    _wait_guardrail_status(bedrock, guardrail["id"], {"READY"}, timeout_s=120.0)
    third = bedrock.create_guardrail_version(guardrailIdentifier=guardrail["id"])
    assert "version" in third, third
    fetched_third = bedrock.get_guardrail(guardrailIdentifier=guardrail["id"], guardrailVersion=third["version"])
    assert fetched_third["version"] == third["version"], (
        f"GetGuardrail did not independently confirm version {third['version']!r}: {fetched_third}"
    )


def _create_guardrail(ctx, bedrock: Any) -> dict[str, str]:
    name = ctx.unique_name("sim2real-bedrock-gr-")
    resp = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="Blocked by guardrail policy.",
        blockedOutputsMessaging="Blocked by guardrail policy.",
        contentPolicyConfig={
            "filtersConfig": [
                {"type": "SEXUAL", "inputStrength": "HIGH", "outputStrength": "HIGH"}
            ]
        },
        tags=[{"key": "sim2real", "value": "guardrail-version-creation-conflict"}],
    )
    guardrail_id = resp["guardrailId"]
    guardrail_arn = resp["guardrailArn"]
    ctx.on_cleanup(lambda: _delete_guardrail(bedrock, guardrail_id))
    _wait_guardrail_status(bedrock, guardrail_id, {"READY"})
    return {"id": guardrail_id, "arn": guardrail_arn}


# Inside the 900 s cleanup budget of behavioral/bedrock.
_TEARDOWN_S = 780.0


def _delete_guardrail(bedrock: Any, guardrail_id: str) -> None:
    """Delete the guardrail; while a version is still being created AWS refuses with
    ValidationException "can't be modified at this time", retried every 2 s to the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _TEARDOWN_S
    while True:
        try:
            bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            busy = error["Code"] == "ValidationException" and (
                "can't be modified at this time" in error.get("Message", "")
            )
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_guardrail_status(
    bedrock: Any,
    guardrail_id: str,
    target_statuses: set[str],
    timeout_s: float = 120.0,
    interval_s: float = 3.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        last_status = resp["status"]
        if last_status in target_statuses:
            return resp
        time.sleep(interval_s)
    raise AssertionError(
        f"guardrail {guardrail_id} did not reach {target_statuses}, last status {last_status}"
    )


def _client_error_code(exc: BaseException) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

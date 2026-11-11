"""guardrail-version-concurrent-calls-get-distinct-versions."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "guardrail-version-concurrent-calls-get-distinct-versions"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateGuardrailVersion calls on one guardrail both succeed with versions 1 and 2,
    both readable, and the next call gets 3; after the guardrail is deleted, CreateGuardrailVersion and
    GetGuardrail return ResourceNotFoundException 'This guardrail does not exist.'"""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-grver-").replace("-", "_")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="blocked input",
        blockedOutputsMessaging="blocked output",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2real-grver-blockedword"}]},
        tags=[{"key": "sim2real", "value": "guardrail-version-conflict-rejected"}],
    )
    guardrail_id = created["guardrailId"]
    delete_registered = False

    def _cleanup():
        if not delete_registered:
            _ignore_not_found(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda s: s in ("READY", "FAILED"),
        timeout_s=120,
    )

    results, errors = [], []

    def _create_version():
        return bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create_version) for _ in range(2)]
        for future in futures:
            try:
                results.append(future.result())
            except Exception as err:  # noqa: BLE001
                errors.append(err)

    assert not errors, f"expected both concurrent creates to succeed, got errors: {errors}"
    assert len(results) == 2, f"expected 2 create_guardrail_version results, got {len(results)}"

    versions = sorted(int(r["version"]) for r in results)
    assert versions == [1, 2], f"expected exactly versions [1, 2] with no duplicate/lost version, got {versions}"

    # Both numbered versions must be independently retrievable (no lost update).
    for version_num in ("1", "2"):
        v = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version_num)
        assert v["version"] == version_num, f"expected get_guardrail version {version_num!r}, got {v['version']!r}"

    # A subsequent call continues the sequence.
    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda s: s in ("READY", "FAILED"),
        timeout_s=120,
    )
    third = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)
    assert third["version"] == "3", f"expected the sequence to continue at version 3, got {third['version']!r}"

    # Boundary case: once the guardrail itself is gone, CreateGuardrailVersion against
    # it is rejected -- not silently accepted or crashing some other way.
    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda s: s in ("READY", "FAILED"),
        timeout_s=120,
    )
    bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)
    delete_registered = True
    # While the delete is in flight the guardrail answers a transient ValidationException;
    # poll past exactly that refusal until the terminal not-found answer.
    code, message = _poll_until(
        lambda: _error(lambda: bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)),
        lambda cm: cm != ("ValidationException", "This guardrail can't be modified at this time."),
        timeout_s=60,
        interval_s=3,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    expected = "This guardrail does not exist."
    assert message == expected, f"expected CreateGuardrailVersion message {expected!r}, got {message!r}"

    # Independent read confirms the guardrail is actually gone, not just that the
    # mutating call happens to refuse it.
    read_code, read_message = _error(lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id))
    assert read_code == "ResourceNotFoundException", (
        f"expected get_guardrail on the deleted guardrail to raise ResourceNotFoundException, got {read_code}"
    )
    expected_read = "This guardrail does not exist."
    assert read_message == expected_read, (
        f"expected GetGuardrail message {expected_read!r}, got {read_message!r}"
    )

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


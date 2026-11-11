"""concurrent-create-same-security-configuration-name."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"

CHECK = "concurrent-create-same-security-configuration-name"
GROUP = 'concurrency'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

def _run_parallel(fns):
    """Run *fns* concurrently, returning (successes, [(code, message), ...])."""
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        successes, errors = [], []
        for future in futures:
            try:
                successes.append(future.result())
            except Exception as exc:
                err = (getattr(exc, "response", {}) or {}).get("Error", {})
                errors.append((err.get("Code", type(exc).__name__), err.get("Message")))
    return successes, errors

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent identical CreateSecurityConfiguration calls for one Name: at least one succeeds,
    any other is throttled or refused with InvalidRequestException and the exact already-exists
    message, and the name is listed exactly once."""
    emr = ctx.client("emr")
    name = _unique_name("emr-secconf-race-")
    payload = (
        '{"EncryptionConfiguration":{"EnableInTransitEncryption":false,'
        '"EnableAtRestEncryption":false}}'
    )
    ctx.on_cleanup(lambda: emr.delete_security_configuration(Name=name))

    def create_one():
        return emr.create_security_configuration(
            Name=name, SecurityConfiguration=payload
        )["Name"]

    results = _run_parallel([create_one for _ in range(4)])
    successes, errors = results
    # A sequential identical re-create is accepted; an overlapping one may instead see the
    # documented duplicate-name refusal. Throttling is tolerated as a rate-limit outcome.
    already_exists = f"SecurityConfiguration with name '{name}' already exists."
    unexpected = [
        (code, msg)
        for code, msg in errors
        if code not in THROTTLE_CODES and (code, msg) != ("InvalidRequestException", already_exists)
    ]
    assert not unexpected, (
        f"concurrent identical creates may only succeed or be refused with InvalidRequestException "
        f"{already_exists!r}, got {unexpected}"
    )
    assert successes, (
        f"at least one concurrent create must succeed, all failed with {errors}"
    )
    assert all(s == name for s in successes), f"unexpected create results: {successes}"

    listed = [
        c["Name"]
        for page in emr.get_paginator("list_security_configurations").paginate()
        for c in page["SecurityConfigurations"]
        if c["Name"] == name
    ]
    assert len(listed) == 1, f"the name must appear exactly once in the listing, got {listed}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

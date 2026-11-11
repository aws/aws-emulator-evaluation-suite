"""concurrent-describe-security-configuration-is-consistent."""
from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _create_security_configuration(emr, ctx, name, payload, track=True):
    last_exc = None
    for attempt in range(6):
        try:
            resp = emr.create_security_configuration(Name=name, SecurityConfiguration=payload)
            if track:
                ctx.on_cleanup(lambda: emr.delete_security_configuration(Name=name))
            return resp
        except Exception as exc:
            code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException") or attempt == 5:
                raise
            last_exc = exc
            time.sleep(5 * (attempt + 1))
    raise AssertionError(f"CreateSecurityConfiguration never succeeded: {last_exc}")

CHECK = "concurrent-describe-security-configuration-is-consistent"
GROUP = 'concurrency'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

def _run_parallel(fns):
    """Run *fns* concurrently, returning (successes, errors_by_code)."""
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        successes, errors = [], []
        for future in futures:
            try:
                successes.append(future.result())
            except Exception as exc:
                errors.append(
                    (getattr(exc, "response", {}) or {})
                    .get("Error", {})
                    .get("Code", type(exc).__name__)
                )
    return successes, errors

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent readers of one security configuration all observe identical
    content — no torn reads, no spurious not-found."""
    emr = ctx.client("emr")
    name = _unique_name("emr-secconf-conc-")
    payload = (
        '{"InstanceMetadataServiceConfiguration":'
        '{"MinimumInstanceMetadataServiceVersion":2,"HttpPutResponseHopLimit":1}}'
    )
    _create_security_configuration(emr, ctx, name, payload)

    def read_one():
        for attempt in range(5):
            try:
                got = emr.describe_security_configuration(Name=name)
                return got["Name"], got["SecurityConfiguration"]
            except Exception as exc:
                code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
                if code not in THROTTLE_CODES or attempt == 4:
                    raise
                time.sleep(2 * (attempt + 1))
        raise AssertionError("unreachable")

    n = 8
    reads, errors = _run_parallel([read_one for _ in range(n)])
    assert not errors, f"concurrent reads of an existing configuration must all succeed, got {errors}"
    assert len(reads) == n, f"expected {n} successful concurrent reads, got {len(reads)}"
    assert len({r[0] for r in reads}) == 1, "concurrent reads disagreed on the Name"
    assert len({r[1] for r in reads}) == 1, "concurrent reads returned differing content"
    assert all(r[0] == name for r in reads), f"expected Name {name!r} on every read, got {[r[0] for r in reads]}"
    expected = json.loads(payload)
    got = json.loads(reads[0][1])
    assert got == expected, f"concurrent reads agreed with each other but not with the created payload: expected {expected}, got {got}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

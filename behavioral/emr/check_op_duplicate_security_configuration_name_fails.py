"""op-duplicate-security-configuration-name-fails."""
from __future__ import annotations

import time
import uuid

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

CHECK = "op-duplicate-security-configuration-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

def _error_stable(fn, attempts: int = 6):
    """Like ``_error`` but retries through throttling so the assertion observes
    the operation's real rejection code rather than a rate-limit artefact."""
    code, message = _error(fn)
    for attempt in range(attempts - 1):
        if code not in THROTTLE_CODES:
            break
        time.sleep(5 * (attempt + 1))
        code, message = _error(fn)
    return code, message

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: a security configuration Name is a unique key — reusing
    it with different content must be rejected, never silently overwritten."""
    emr = ctx.client("emr")
    name = _unique_name("emr-secconf-dup-")
    original = (
        '{"EncryptionConfiguration":{"EnableInTransitEncryption":false,'
        '"EnableAtRestEncryption":false}}'
    )
    different = '{"InstanceMetadataServiceConfiguration":{"MinimumInstanceMetadataServiceVersion":2,"HttpPutResponseHopLimit":1}}'

    _create_security_configuration(emr, ctx, name, original)

    code, message = _error_stable(
        lambda: emr.create_security_configuration(Name=name, SecurityConfiguration=different)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"SecurityConfiguration with name '{name}' already exists.", message

    # The original content must survive the rejected overwrite.
    stored = emr.describe_security_configuration(Name=name)["SecurityConfiguration"]
    assert "EncryptionConfiguration" in stored, (
        f"rejected duplicate must not have replaced the stored configuration, got {stored}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

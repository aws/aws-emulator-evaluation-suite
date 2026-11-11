"""op-security-configuration-delete-is-not-idempotent."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _delete_if_present(emr, name):
    """Teardown delete that tolerates the check having deleted the configuration itself."""
    try:
        emr.delete_security_configuration(Name=name)
    except Exception as exc:  # noqa: BLE001
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        if err.get("Code") != "InvalidRequestException" or "does not exist" not in err.get("Message", ""):
            raise


def _create_security_configuration(emr, ctx, name, payload, track=True):
    last_exc = None
    for attempt in range(6):
        try:
            resp = emr.create_security_configuration(Name=name, SecurityConfiguration=payload)
            if track:
                ctx.on_cleanup(lambda: _delete_if_present(emr, name))
            return resp
        except Exception as exc:
            code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException") or attempt == 5:
                raise
            last_exc = exc
            time.sleep(5 * (attempt + 1))
    raise AssertionError(f"CreateSecurityConfiguration never succeeded: {last_exc}")

CHECK = "op-security-configuration-delete-is-not-idempotent"
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
    """OVERLY-PERMISSIVE: DeleteSecurityConfiguration is not a silent no-op —
    deleting a name twice must fail the second time."""
    emr = ctx.client("emr")
    name = _unique_name("emr-secconf-twice-")
    payload = (
        '{"EncryptionConfiguration":{"EnableInTransitEncryption":false,'
        '"EnableAtRestEncryption":false}}'
    )
    _create_security_configuration(emr, ctx, name, payload, track=True)
    emr.delete_security_configuration(Name=name)

    code, message = _error_stable(lambda: emr.delete_security_configuration(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = f'Security configuration with name "{name}" does not exist.'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    names = [c["Name"] for c in emr.list_security_configurations()["SecurityConfigurations"]]
    assert name not in names, "a deleted security configuration must stay deleted"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""op-malformed-security-configuration-json-fails."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"

CHECK = "op-malformed-security-configuration-json-fails"
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
    """CreateSecurityConfiguration rejects malformed JSON with InvalidRequestException "Invalid security
    configuration; Malformed Json string." and stores nothing, while a well-formed document is stored verbatim."""
    emr = ctx.client("emr")
    bad_name = _unique_name("emr-secconf-bad-")
    good_name = _unique_name("emr-secconf-good-")

    code, message = _error_stable(
        lambda: emr.create_security_configuration(
            Name=bad_name, SecurityConfiguration="this-is-not-json"
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Invalid security configuration; Malformed Json string.", (
        f"expected AWS's exact malformed-JSON message, got {message!r}"
    )

    names = [c["Name"] for c in emr.list_security_configurations()["SecurityConfigurations"]]
    assert bad_name not in names, "a rejected security configuration must not be persisted"

    # positive control: a well-formed document is accepted, persisted, and reads back unchanged —
    # registered before the resource exists.
    valid_doc = {
        "EncryptionConfiguration": {
            "EnableInTransitEncryption": False,
            "EnableAtRestEncryption": False,
        }
    }
    ctx.on_cleanup(lambda: emr.delete_security_configuration(Name=good_name))
    emr.create_security_configuration(Name=good_name, SecurityConfiguration=json.dumps(valid_doc))

    described = emr.describe_security_configuration(Name=good_name)
    assert described["Name"] == good_name, f"unexpected describe response {described!r}"
    assert json.loads(described["SecurityConfiguration"]) == valid_doc, (
        f"the accepted configuration did not round-trip: "
        f"{described['SecurityConfiguration']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""delete-security-configuration-then-describe-fails."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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

CHECK = "delete-security-configuration-then-describe-fails"
GROUP = 'security-configuration'
SERVICES = ['emr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteSecurityConfiguration, DescribeSecurityConfiguration must no longer find it,
    and the freed name must be a reusable identifier, not permanently retired."""
    emr = ctx.client("emr")
    name = _unique_name("emr-secconf-del-")
    payload = '{"EncryptionConfiguration":{"EnableInTransitEncryption":false,"EnableAtRestEncryption":false}}'

    _create_security_configuration(emr, ctx, name, payload, track=False)
    emr.delete_security_configuration(Name=name)

    code, message = _error(lambda: emr.describe_security_configuration(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f'Security configuration with name "{name}" does not exist.', message

    names = [c["Name"] for c in emr.list_security_configurations()["SecurityConfigurations"]]
    assert name not in names, "a deleted configuration must disappear from the listing too"

    _create_security_configuration(emr, ctx, name, payload, track=True)
    recreated = emr.describe_security_configuration(Name=name)
    assert recreated["Name"] == name, f"expected the freed name to be reusable, got {recreated}"
    names_after_recreate = [c["Name"] for c in emr.list_security_configurations()["SecurityConfigurations"]]
    assert name in names_after_recreate, "the recreated configuration must reappear in the listing"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""security-configuration-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message, modeled ErrorCode). An
    unexpected success raises. EMR's InvalidRequestException carries the discriminator in ErrorCode."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
            exc.response.get("ErrorCode"),
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_if_present(emr, name):
    """Teardown: delete the security configuration, tolerating one the check already deleted."""
    try:
        emr.delete_security_configuration(Name=name)
    except ClientError as exc:
        if exc.response.get("ErrorCode") != "ResourceNotFound":
            raise


def _listed_names(emr):
    return [
        c["Name"]
        for page in emr.get_paginator("list_security_configurations").paginate()
        for c in page["SecurityConfigurations"]
    ]


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

CHECK = "security-configuration-roundtrip"
GROUP = 'security-configuration'
SERVICES = ['emr']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecurityConfiguration persists the exact JSON payload, retrievable by name; deleted, it is gone."""
    emr = ctx.client("emr")
    name = ctx.unique_name("sim2real-behav-emr-secconf-")
    payload = {
        "EncryptionConfiguration": {
            "EnableInTransitEncryption": False,
            "EnableAtRestEncryption": False,
        }
    }

    _create_security_configuration(emr, ctx, name, json.dumps(payload))

    desc = emr.describe_security_configuration(Name=name)
    assert desc["Name"] == name, f"expected Name={name!r}, got {desc.get('Name')!r}"
    stored = json.loads(desc["SecurityConfiguration"])
    assert stored == payload, f"expected persisted payload {payload!r}, got {stored!r}"

    assert name in _listed_names(emr), "created security configuration missing from ListSecurityConfigurations"

    # Delete it, then prove it gone: unreadable, unlisted, and not deletable again.
    emr.delete_security_configuration(Name=name)
    code, status, message, detail = _error(lambda: emr.describe_security_configuration(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for the deleted name, got {code}"
    assert detail == "ResourceNotFound", f"expected ErrorCode ResourceNotFound for the deleted name, got {detail!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected an HTTP 4xx describing the deleted security configuration, got {status!r}"
    assert message, "expected a non-empty not-found message"
    assert name not in _listed_names(emr), "the deleted security configuration is still listed"
    code, status, message, detail = _error(lambda: emr.delete_security_configuration(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException re-deleting the dead name, got {code}"
    assert detail == "ResourceNotFound", f"expected ErrorCode ResourceNotFound re-deleting the dead name, got {detail!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected an HTTP 4xx re-deleting the dead security configuration, got {status!r}"
    assert message, "expected a non-empty re-delete not-found message"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

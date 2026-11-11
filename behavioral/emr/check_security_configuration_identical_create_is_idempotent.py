"""security-configuration-identical-create-is-idempotent."""
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

CHECK = "security-configuration-identical-create-is-idempotent"
GROUP = 'security-configuration'
SERVICES = ['emr']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-creating a security configuration with byte-identical content is accepted
    (idempotent), leaving exactly one configuration under that Name."""
    emr = ctx.client("emr")
    name = _unique_name("emr-secconf-idem-")
    payload = (
        '{"EncryptionConfiguration":{"EnableInTransitEncryption":false,'
        '"EnableAtRestEncryption":false}}'
    )

    _create_security_configuration(emr, ctx, name, payload)
    before = emr.describe_security_configuration(Name=name)["SecurityConfiguration"]

    # Identical re-create must NOT raise (contrast: differing content is rejected).
    _create_security_configuration(emr, ctx, name, payload, track=False)

    after = emr.describe_security_configuration(Name=name)["SecurityConfiguration"]
    assert after == before, "an idempotent re-create must not alter stored content"

    matches = [
        c
        for page in emr.get_paginator("list_security_configurations").paginate()
        for c in page["SecurityConfigurations"]
        if c["Name"] == name
    ]
    assert len(matches) == 1, f"expected exactly one entry for the name, got {len(matches)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

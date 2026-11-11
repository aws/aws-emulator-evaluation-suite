"""security-configuration-creation-timestamp-is-current."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

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

CHECK = "security-configuration-creation-timestamp-is-current"
GROUP = 'security-configuration'
SERVICES = ['emr']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecurityConfigurations/Describe report a server-side CreationDateTime
    that is genuinely 'now', not a placeholder."""
    emr = ctx.client("emr")
    name = _unique_name("emr-secconf-time-")
    payload = (
        '{"EncryptionConfiguration":{"EnableInTransitEncryption":false,'
        '"EnableAtRestEncryption":false}}'
    )
    before = datetime.now(timezone.utc) - timedelta(minutes=10)
    _create_security_configuration(emr, ctx, name, payload)
    after = datetime.now(timezone.utc) + timedelta(minutes=10)

    described = emr.describe_security_configuration(Name=name)
    created = described["CreationDateTime"]
    assert before <= created <= after, (
        f"CreationDateTime {created} is not within the request window [{before}, {after}]"
    )

    matches = [
        c
        for page in emr.get_paginator("list_security_configurations").paginate()
        for c in page["SecurityConfigurations"]
        if c["Name"] == name
    ]
    assert matches, f"{name} missing from ListSecurityConfigurations"
    summary = matches[0]
    assert summary["CreationDateTime"] == created, (
        "ListSecurityConfigurations and DescribeSecurityConfiguration must agree on "
        f"CreationDateTime ({summary['CreationDateTime']} vs {created})"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

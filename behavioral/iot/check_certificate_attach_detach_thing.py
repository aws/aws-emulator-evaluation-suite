"""certificate-attach-detach-thing."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "certificate-attach-detach-thing"
GROUP = 'certificate-lifecycle'
SERVICES = ['iot']

def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT propagates registry/job writes asynchronously, so the first few
    reads can raise ResourceNotFoundException before settling.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")

def _delete_certificate(iot, cert_id):
    """Teardown: detach policies/things, deactivate, then force-delete; a missing certificate is clean."""
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"
        ]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        cert_arn = None
    if cert_arn:
        try:
            for p in iot.list_attached_policies(target=cert_arn).get("policies", []):
                iot.detach_policy(policyName=p["policyName"], target=cert_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            for t in iot.list_principal_things(principal=cert_arn).get("things", []):
                try:
                    iot.detach_thing_principal(thingName=t, principal=cert_arn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Attaching/detaching a certificate principal to a thing updates both listing directions."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-behav-thing-cert-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    iot.attach_thing_principal(thingName=thing, principal=cert_arn)
    principals = _eventually(
        lambda: iot.list_thing_principals(thingName=thing).get("principals", []),
        lambda ps: cert_arn in ps,
        timeout_s=90,
        interval_s=3,
    )
    assert cert_arn in principals, principals

    things_for_principal = _eventually(
        lambda: iot.list_principal_things(principal=cert_arn).get("things", []),
        lambda ts: thing in ts,
        timeout_s=90,
        interval_s=3,
    )
    assert thing in things_for_principal, things_for_principal

    iot.detach_thing_principal(thingName=thing, principal=cert_arn)
    principals_after = _eventually(
        lambda: iot.list_thing_principals(thingName=thing).get("principals", []),
        lambda ps: cert_arn not in ps,
        timeout_s=90,
        interval_s=3,
    )
    assert cert_arn not in principals_after, principals_after

    things_for_principal_after = _eventually(
        lambda: iot.list_principal_things(principal=cert_arn).get("things", []),
        lambda ts: thing not in ts,
        timeout_s=90,
        interval_s=3,
    )
    assert thing not in things_for_principal_after, things_for_principal_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

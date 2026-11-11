"""iot-delete-thing-with-an-attached-principal-is-refused-and-the-attachment-survives."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iot-delete-thing-with-an-attached-principal-is-refused-and-the-attachment-survives"
GROUP = 'registry-rejection'
SERVICES = ['iot']


def _error(fn):
    """The AWS (code, HTTP status, message) raised by ``fn``. An unexpected success RAISES.

    An unexpected success is the strongest signal available -- the target accepted input real
    AWS rejects -- so it must fail loudly, never come back as a value that reads like a code.
    """
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - the code is the subject of the assertion
        resp = getattr(exc, "response", None) or {}
        error = resp.get("Error") or {}
        code = error.get("Code")
        if not code:
            raise
        return code, (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _detach_if_attached(iot, thing: str, principal: str) -> None:
    """Teardown: detach, tolerating a thing the check itself already deleted."""
    try:
        iot.detach_thing_principal(thingName=thing, principal=principal)
    except Exception as exc:  # noqa: BLE001 - only a missing thing is tolerated
        code = ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code")
        if code != "ResourceNotFoundException":
            raise


def _principals(iot, thing: str) -> list[str]:
    """Every principal of ``thing``, fully paginated.

    The account is shared and a thing can carry many principals; an unpaginated read is a
    latent flake that would look like a fidelity gap.
    """
    out: list[str] = []
    for page in iot.get_paginator("list_thing_principals").paginate(thingName=thing):
        out += page.get("principals", [])
    return out


def _deactivate_and_delete_cert(iot, cert_id: str) -> None:
    """A certificate cannot be deleted while ACTIVE or while any principal attachment remains."""
    try:
        arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        arn = None
    if arn:
        for thing in iot.list_principal_things(principal=arn).get("things", []):
            try:
                iot.detach_thing_principal(thingName=thing, principal=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    iot.delete_certificate(certificateId=cert_id, forceDelete=True)


def _delete_thing_if_present(iot, thing: str) -> None:
    try:
        iot.delete_thing(thingName=thing)
    except iot.exceptions.ResourceNotFoundException:
        pass


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DeleteThing is refused while a certificate is attached, the refusal changes nothing (the
    thing still describes and keeps the certificate as a principal), and the identical delete
    succeeds once the principal is detached."""
    iot = ctx.client("iot")
    thing = ctx.unique_name("sim2real-iot-thing-")

    iot.create_thing(thingName=thing, attributePayload={"attributes": {"sim2real": "thing-principal"}})
    ctx.on_cleanup(lambda: _delete_thing_if_present(iot, thing))

    cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_id, cert_arn = cert["certificateId"], cert["certificateArn"]
    ctx.on_cleanup(lambda: _deactivate_and_delete_cert(iot, cert_id))

    iot.attach_thing_principal(thingName=thing, principal=cert_arn)
    ctx.on_cleanup(lambda: _detach_if_attached(iot, thing, cert_arn))
    attached = _principals(iot, thing)
    assert cert_arn in attached, f"the attach did not take: {attached!r}"

    code, status, message = _error(lambda: iot.delete_thing(thingName=thing))
    assert code == "InvalidRequestException", (
        f"DeleteThing on a thing with an attached certificate raised {code!r}"
    )
    assert status == 400, f"the refusal must be HTTP 400, got {status!r}"
    expected_message = f"Cannot delete. Thing {thing} is still attached to one or more principals"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    described = iot.describe_thing(thingName=thing)
    assert described["thingName"] == thing, f"{described!r}"
    survived = _principals(iot, thing)
    assert cert_arn in survived, (
        f"the refused DeleteThing detached the principal anyway: {survived!r}"
    )

    # Remove exactly the one blocking attachment.
    iot.detach_thing_principal(thingName=thing, principal=cert_arn)
    deadline = time.time() + 60
    remaining = _principals(iot, thing)
    while remaining and time.time() < deadline:
        time.sleep(2)
        remaining = _principals(iot, thing)
    assert remaining == [], f"the detach never settled; principals still {remaining!r}"

    # POSITIVE CONTROL: the identical DeleteThing now succeeds and the thing is really gone.
    iot.delete_thing(thingName=thing)
    gone_code, gone_status, gone_message = _error(lambda: iot.describe_thing(thingName=thing))
    assert gone_code == "ResourceNotFoundException", (
        f"DescribeThing after a successful delete raised {gone_code!r}"
    )
    assert gone_status == 404, f"DescribeThing on the deleted thing must be HTTP 404, got {gone_status!r}"
    expected_message = f"Thing {ctx.account}:{thing} not found."
    assert gone_message == expected_message, f"expected the message {expected_message!r}, got {gone_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

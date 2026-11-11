"""delete-domain-then-get-returns-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-domain-then-get-returns-not-found"
GROUP = "state"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomain moves ACTIVE -> DELETING (or completes synchronously to DELETED), and GetDomain eventually 404s."""
    ch = ctx.client("connecthealth")
    name = ctx.unique_name("sim2real-conh-dom-")
    domain_id = _create_domain(ch, name)["domainId"]

    def _cleanup():
        try:
            ch.delete_domain(domainId=domain_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    delete_resp = ch.delete_domain(domainId=domain_id)
    assert delete_resp["domainId"] == domain_id, f"expected domainId {domain_id!r}, got {delete_resp['domainId']!r}"
    assert delete_resp["status"] in ("DELETING", "DELETED"), f"unexpected status {delete_resp['status']!r}"

    deadline = time.monotonic() + 60.0
    code = message = None
    while time.monotonic() < deadline:
        try:
            ch.get_domain(domainId=domain_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            break
        time.sleep(2.0)
    expected = f"Domain not found: {domain_id}"
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # mutation on the dead id also fails, with the same specific code
    second_delete_code = second_delete_message = None
    try:
        ch.delete_domain(domainId=domain_id)
    except ClientError as err:
        second_delete_code = err.response["Error"]["Code"]
        second_delete_message = err.response["Error"].get("Message", "")
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on double delete, got {second_delete_code!r}"
    )
    assert second_delete_message == expected, f"expected message {expected!r}, got {second_delete_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

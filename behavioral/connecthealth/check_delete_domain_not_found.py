"""delete-domain-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-domain-not-found"
GROUP = "error-semantics"
SERVICES = ["connecthealth"]


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomain on a domainId never allocated to any account returns
    AuthorizerConfigurationException with an empty Message, not the modelled
    ResourceNotFoundException, while DeleteDomain on a real Domain succeeds."""
    ch = ctx.client("connecthealth")

    fake_domain_id = "dom-" + "2" * 20  # matches ^(hai-|dom-)[a-z0-9]+$, 20-25 chars, never allocated
    code, message = _client_error(lambda: ch.delete_domain(domainId=fake_domain_id))
    assert code == "AuthorizerConfigurationException", f"expected AuthorizerConfigurationException, got {code!r}"
    assert message is None, f"expected AuthorizerConfigurationException with a null message, got {message!r}"

    # positive control: deleting a real Domain succeeds
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]

    def _cleanup():
        try:
            ch.delete_domain(domainId=domain_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    delete_resp = ch.delete_domain(domainId=domain_id)
    assert delete_resp["domainId"] == domain_id
    assert delete_resp["status"] in ("DELETING", "DELETED"), f"unexpected status {delete_resp['status']!r}"

    # independent read: the deletion actually took effect, not just the mutating call's own echo
    deadline = time.monotonic() + 60.0
    get_code = get_message = None
    while time.monotonic() < deadline:
        try:
            ch.get_domain(domainId=domain_id)
        except ClientError as err:
            get_code = err.response["Error"]["Code"]
            get_message = err.response["Error"].get("Message", "")
            break
        time.sleep(2.0)
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {get_code!r}"
    expected = f"Domain not found: {domain_id}"
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

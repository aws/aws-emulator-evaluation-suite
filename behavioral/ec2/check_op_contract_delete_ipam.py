"""op-contract-delete-ipam."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-ipam"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpam deletes a new IPAM with no pools, which reaches delete-complete; deleting that IPAM again
    and deleting a never-created IPAM ID both fail with InvalidIpamId.NotFound and the exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ipam-")

    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True)))

    resp = ec2.delete_ipam(IpamId=ipam_id)
    assert resp["Ipam"]["IpamId"] == ipam_id
    assert resp["Ipam"]["State"] in ("delete-in-progress", "delete-complete"), resp["Ipam"]

    def probe():
        from botocore.exceptions import ClientError

        try:
            ipams = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"]
        except ClientError:
            return "delete-complete"
        return ipams[0]["State"] if ipams else "delete-complete"

    state = _poll_until(probe, lambda s: s in ("delete-complete",), timeout_s=60, interval_s=3)
    assert state == "delete-complete", state

    # Error boundary: this specific IPAM is now dead, so deleting it again is rejected too --
    # not just format-rejected, but rejected as *this* resource being gone.
    dead_code, dead_message = _error(lambda: ec2.delete_ipam(IpamId=ipam_id))
    assert dead_code == "InvalidIpamId.NotFound", f"unexpected code deleting the dead ipam: {dead_code!r}"
    assert dead_message == f"The IPAM ({ipam_id}) does not exist.", f"unexpected message {dead_message!r}"

    # Distinct error boundary: an unknown IPAM ID that was never created is rejected too.
    fake_id = _zeroed_id(ipam_id)
    code, message = _error(lambda: ec2.delete_ipam(IpamId=fake_id))
    assert code == "InvalidIpamId.NotFound", f"unexpected code deleting an unknown ipam: {code!r}"
    assert message == f"The IPAM ({fake_id}) does not exist.", f"unexpected message {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamId.NotFound":
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

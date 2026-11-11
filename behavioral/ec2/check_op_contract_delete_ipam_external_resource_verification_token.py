"""op-contract-delete-ipam-external-resource-verification-token."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-ipam-external-resource-verification-token"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamExternalResourceVerificationToken deletes a new token, which reaches delete-complete;
    deleting it again and deleting a never-created token ID both fail with
    InvalidIpamExternalResourceVerificationTokenId.NotFound and the exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ipamtok-")

    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True)))

    token = ec2.create_ipam_external_resource_verification_token(
        IpamId=ipam_id,
        TagSpecifications=[
            {"ResourceType": "ipam-external-resource-verification-token", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["IpamExternalResourceVerificationToken"]
    token_id = token["IpamExternalResourceVerificationTokenId"]
    ctx.on_cleanup(
        lambda: _ignore(
            lambda: ec2.delete_ipam_external_resource_verification_token(
                IpamExternalResourceVerificationTokenId=token_id
            )
        )
    )

    resp = ec2.delete_ipam_external_resource_verification_token(
        IpamExternalResourceVerificationTokenId=token_id
    )
    deleted = resp["IpamExternalResourceVerificationToken"]
    assert deleted["IpamExternalResourceVerificationTokenId"] == token_id
    assert deleted["State"] in ("delete-in-progress", "delete-complete"), deleted

    def probe():
        from botocore.exceptions import ClientError

        try:
            tokens = ec2.describe_ipam_external_resource_verification_tokens(
                IpamExternalResourceVerificationTokenIds=[token_id]
            )["IpamExternalResourceVerificationTokens"]
        except ClientError:
            return "delete-complete"
        return tokens[0]["State"] if tokens else "delete-complete"

    state = _poll_until(probe, lambda s: s == "delete-complete", timeout_s=60, interval_s=3)
    assert state == "delete-complete", state

    # Error boundary: this specific token is now dead, so deleting it again is rejected too --
    # not just format-rejected, but rejected as *this* resource being gone.
    dead_code, dead_message = _error(
        lambda: ec2.delete_ipam_external_resource_verification_token(
            IpamExternalResourceVerificationTokenId=token_id
        )
    )
    assert dead_code == "InvalidIpamExternalResourceVerificationTokenId.NotFound", f"unexpected code {dead_code!r}"
    assert dead_message == f"The ipam-external-resource-verification-token ID '{token_id}' does not exist", f"unexpected message {dead_message!r}"

    # Distinct error boundary: an unknown token ID that was never created is rejected too.
    fake_id = _zeroed_id(token_id)
    code, message = _error(
        lambda: ec2.delete_ipam_external_resource_verification_token(
            IpamExternalResourceVerificationTokenId=fake_id
        )
    )
    assert code == "InvalidIpamExternalResourceVerificationTokenId.NotFound", f"unexpected code {code!r}"
    assert message == f"The ipam-external-resource-verification-token ID '{fake_id}' does not exist", f"unexpected message {message!r}"


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
        if exc.response["Error"]["Code"] not in (
            "InvalidIpamExternalResourceVerificationTokenId.NotFound",
            "InvalidIpamId.NotFound",
        ):
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

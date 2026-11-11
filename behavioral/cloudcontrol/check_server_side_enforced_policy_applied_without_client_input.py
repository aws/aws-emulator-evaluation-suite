"""server-side-enforced-policy-applied-without-client-input."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-enforced-policy-applied-without-client-input"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::S3::Bucket"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A bucket created via Cloud Control with only a BucketName shows S3's default Block Public
    Access (all four flags True) and SSE-S3 (AES256) default encryption on GetResource.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
    """
    cc = ctx.client("cloudcontrol")
    bucket_name = ctx.unique_name("sim2real-cc-bucket-")

    resp = cc.create_resource(TypeName=_TYPE_NAME, DesiredState=json.dumps({"BucketName": bucket_name}))
    token = resp["ProgressEvent"]["RequestToken"]
    pe = _wait_for_terminal(cc, token, timeout_s=120.0)
    assert pe["OperationStatus"] == "SUCCESS", f"bucket create did not succeed: {pe}"
    identifier = pe["Identifier"]
    ctx.on_cleanup(lambda: _cleanup_delete(cc, _TYPE_NAME, identifier))

    get_resp = cc.get_resource(TypeName=_TYPE_NAME, Identifier=identifier)
    props = json.loads(get_resp["ResourceDescription"]["Properties"])

    pab = props.get("PublicAccessBlockConfiguration")
    assert pab is not None, (
        "expected the account-wide S3 Block Public Access default to be reflected on "
        "GetResource even though DesiredState never set PublicAccessBlockConfiguration"
    )
    assert pab.get("BlockPublicAcls") is True, f"expected BlockPublicAcls=True by default, got {pab}"
    assert pab.get("BlockPublicPolicy") is True, f"expected BlockPublicPolicy=True by default, got {pab}"
    assert pab.get("IgnorePublicAcls") is True, f"expected IgnorePublicAcls=True by default, got {pab}"
    assert pab.get("RestrictPublicBuckets") is True, f"expected RestrictPublicBuckets=True by default, got {pab}"

    enc = props.get("BucketEncryption")
    assert enc is not None, (
        "expected the account-wide S3 default encryption (SSE-S3) to be reflected on "
        "GetResource even though DesiredState never set BucketEncryption"
    )
    rules = enc.get("ServerSideEncryptionConfiguration", [])
    assert len(rules) >= 1, f"expected at least one default encryption rule, got {enc}"
    default_sse = rules[0].get("ServerSideEncryptionByDefault", {})
    assert default_sse.get("SSEAlgorithm") == "AES256", f"expected default SSEAlgorithm=AES256, got {enc}"


_TERMINAL = ("SUCCESS", "FAILED", "CANCEL_COMPLETE")


def _wait_for_terminal(cc, token, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached terminal state (last={last})")


def _cleanup_delete(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_for_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

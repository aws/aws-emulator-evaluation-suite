"""send-alexa-offer-to-master-malformed-arn-and-no-master-error-semantics."""
from __future__ import annotations

import base64
import time
from urllib.parse import urlencode

from behavioral_harness import tags

CHECK = "send-alexa-offer-to-master-malformed-arn-and-no-master-error-semantics"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The "SendAlexaOfferToMaster" call rejects a malformed ChannelARN with InvalidArgumentException and the exact
    message "Invalid Channel ARN !"; a well-formed offer to an ACTIVE channel with no primary peer
    connected returns HTTP 200 with no Answer member."""

    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-alexabad-")
    arn = kv.create_signaling_channel(ChannelName=name, ChannelType="SINGLE_MASTER")["ChannelARN"]
    ctx.on_cleanup(lambda: kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")

    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)
    sender_client_id = ctx.unique_name("alexa-")
    well_formed_b64 = base64.b64encode(b"well-formed-sdp-offer-no-master-yet").decode()

    # negative: a ChannelARN that fails the modeled pattern is rejected before any delivery
    # attempt is even considered.
    malformed_arn = arn + "x"
    err = _error(
        lambda: sig.send_alexa_offer_to_master(
            ChannelARN=malformed_arn,
            SenderClientId=sender_client_id,
            MessagePayload=well_formed_b64,
        )
    )
    assert err["Code"] == "InvalidArgumentException", f"expected InvalidArgumentException, got {err!r}"
    assert err["Message"] == "Invalid Channel ARN !", (
        f"unexpected InvalidArgumentException message: {err['Message']!r}"
    )

    # With no "MASTER" peer connected, a well-formed request to an ACTIVE channel is not refused:
    # it blocks for the redelivery window and returns HTTP 200 with no "Answer" member.
    resp = sig.send_alexa_offer_to_master(
        ChannelARN=arn,
        SenderClientId=sender_client_id,
        MessagePayload=well_formed_b64,
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 for a well-formed offer with no 'MASTER' peer, got {status!r}"
    assert "Answer" not in resp, f"expected no Answer for an offer with no 'MASTER' peer, got {resp!r}"


def _wait_channel_status(ctx, name, target_status, timeout_s=60.0, interval_s=1.5):
    kv = ctx.client("kinesisvideo")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kv.describe_signaling_channel(ChannelName=name)["ChannelInfo"]
        last = info.get("ChannelStatus")
        if last == target_status:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"channel {name!r} did not reach status {target_status!r}; last seen {last!r}")


def _get_endpoint(ctx, channel_arn, protocol, role):
    kv = ctx.client("kinesisvideo")
    resp = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": [protocol], "Role": role},
    )
    for entry in resp["ResourceEndpointList"]:
        if entry["Protocol"] == protocol:
            return entry["ResourceEndpoint"]
    raise AssertionError(f"no {protocol} endpoint returned for channel {channel_arn}")


def _presigned_wss_url(ctx, wss_endpoint, channel_arn, client_id=None):
    from botocore.auth import SigV4QueryAuth
    from botocore.awsrequest import AWSRequest

    creds = ctx.client("kinesisvideo")._request_signer._credentials.get_frozen_credentials()
    params = {"X-Amz-ChannelARN": channel_arn}
    if client_id:
        params["X-Amz-ClientId"] = client_id
    request = AWSRequest(method="GET", url=f"{wss_endpoint}?{urlencode(params)}")
    SigV4QueryAuth(creds, "kinesisvideo", ctx.region, expires=299).add_auth(request)
    return request.url


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


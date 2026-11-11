"""get-delegated-access-token-returns-usable-credentials."""
from __future__ import annotations

import re
from urllib.parse import quote

import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-delegated-access-token-returns-usable-credentials"
GROUP = "data-plane"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetDelegatedAccessToken fails ValidationError 'Invalid trade-in token' for a never-issued
    token and the must-not-be-null message when TradeInToken is absent; GetCallerIdentity is the
    control that the caller's STS access is healthy.
    """
    sts = ctx.client("sts")

    # Control: the rejections below are not a blanket denial of this caller.
    identity = sts.get_caller_identity()
    assert identity.get("Account"), identity

    garbage_token = "sim2real-behavioral-check-never-issued-trade-in-token-0123456789"
    code_garbage, message_garbage = _error(
        lambda: sts.get_delegated_access_token(TradeInToken=garbage_token)
    )
    assert code_garbage == "ValidationError", code_garbage
    assert message_garbage == "Invalid trade-in token", message_garbage

    code_absent, message_absent = _raw_get_delegated_access_token_error(
        sts, ctx.region, ctx.http_verify
    )
    assert code_absent == "ValidationError", (code_absent, message_absent)
    assert message_absent == (
        "1 validation error detected: Value at 'tradeInToken' failed to satisfy constraint: "
        "Member must not be null"
    ), message_absent


def _raw_get_delegated_access_token_error(
    sts_client, region: str, verify
) -> tuple[str | None, str]:
    """POST a hand-signed GetDelegatedAccessToken request with no TradeInToken, bypassing
    botocore's required-parameter check, and return the <Code>/<Message> from the error XML."""
    endpoint = sts_client.meta.endpoint_url.rstrip("/") + "/"
    creds = sts_client._request_signer._credentials
    params = {"Action": "GetDelegatedAccessToken", "Version": "2011-06-15"}
    body = "&".join(f"{quote(k, safe='')}={quote(str(v), safe='')}" for k, v in params.items())
    req = AWSRequest(
        method="POST",
        url=endpoint,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    SigV4Auth(creds, "sts", region).add_auth(req)
    resp = requests.post(
        endpoint, data=body.encode("utf-8"), headers=dict(req.headers), timeout=20,
        verify=verify,
    )
    code_match = re.search(r"<Code>([^<]+)</Code>", resp.text)
    message_match = re.search(r"<Message>([^<]*)</Message>", resp.text)
    code = code_match.group(1) if code_match else f"HTTP{resp.status_code}"
    message = message_match.group(1) if message_match else resp.text[:300]
    return code, message


def _error(fn):
    """fn()'s error (code, message); a success raises because the token was never issued."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"GetDelegatedAccessToken issued credentials for a never-issued TradeInToken: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

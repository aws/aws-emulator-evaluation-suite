"""put-outbound-request-batch-invalid-client-token-pattern-rejected."""
from __future__ import annotations

import datetime
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-outbound-request-batch-invalid-client-token-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutOutboundRequestBatch on an unknown campaign answers a pattern-valid clientToken with the exact
    ResourceNotFoundException, and a clientToken outside ^[a-zA-Z0-9_\\-.]*$ with the exact
    ValidationException: shape validation runs before the campaign lookup."""
    campaigns = ctx.client("connectcampaignsv2")
    fake_campaign_id = str(uuid.uuid4())
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

    def _request(client_token):
        return {
            "clientToken": client_token,
            "expirationTime": expiration,
            "channelSubtypeParameters": {
                "telephony": {
                    "destinationPhoneNumber": "+15555550100",
                    "attributes": {},
                }
            },
        }

    def _put_batch(client_token):
        campaigns.put_outbound_request_batch(
            id=fake_campaign_id,
            outboundRequests=[_request(client_token)],
        )

    positive = _error(lambda: _put_batch(str(uuid.uuid4())))
    assert positive["Code"] == "ResourceNotFoundException", (
        f"positive control (pattern-valid clientToken) expected to reach the campaign lookup "
        f"and fail with ResourceNotFoundException, got {positive['Code']}"
    )
    expected_positive = f"Campaign: {fake_campaign_id} doesn't exist"
    assert positive["Message"] == expected_positive, (
        f"expected message {expected_positive!r}, got {positive['Message']!r}"
    )

    bad_token = "bad token! not allowed"
    err = _error(lambda: _put_batch(bad_token))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']}"
    expected = (
        '{ "message": "1 validation error detected: '
        f"Value '{bad_token}' at 'outboundRequests.1.member.clientToken' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_\\-.]*\" }"
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

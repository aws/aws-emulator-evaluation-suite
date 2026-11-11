"""get-listing-denied-principal-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-listing-denied-principal-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IAM principal with an explicit Deny on aws-marketplace:GetListing gets AccessDeniedException, while the default caller still succeeds."""
    from botocore.exceptions import ClientError

    client = ctx.client("marketplace-discovery")
    resp = client.search_listings(maxResults=1)
    summaries = resp.get("listingSummaries", [])
    if not summaries:
        raise AssertionError("no listings visible to this account to use as a positive control")
    listing_id = summaries[0]["listingId"]

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-mktdisc-deny-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "deny-get-listing"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "aws-marketplace:GetListing",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key["AccessKeyId"])
    )

    restricted = ctx.client(
        "marketplace-discovery",
        creds={
            "aws_access_key_id": access_key["AccessKeyId"],
            "aws_secret_access_key": access_key["SecretAccessKey"],
        },
    )

    # New IAM credentials/policies can take a few seconds to propagate, and a key that has not
    # propagated yet is refused with the same AccessDeniedException code but an invalid-token
    # message; poll until the explicit-deny decision itself is returned.
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"aws-marketplace:GetListing on resource: "
        f"arn:aws:aws-marketplace:::catalog/AWSMarketplace/listing/{listing_id} "
        f"with an explicit deny in an identity-based policy"
    )
    error = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            result = restricted.get_listing(listingId=listing_id)
        except ClientError as e:
            error = e.response.get("Error", {})
            if error.get("Message") == expected_message:
                break
        else:
            raise AssertionError(
                f"a principal with an explicit Deny on GetListing was allowed; got {result!r}"
            )
        time.sleep(2.0)

    assert error is not None and error.get("Code") == "AccessDeniedException", (
        f"expected AccessDeniedException for a principal with an explicit Deny, got {error!r}"
    )
    assert error.get("Message") == expected_message, (
        f"expected the explicit-deny message {expected_message!r}, got {error.get('Message')!r}"
    )

    # positive control: the default (non-denied) caller can still read the same listing
    control = client.get_listing(listingId=listing_id)
    assert control["listingId"] == listing_id, (
        f"expected the default (non-denied) caller to still read listingId={listing_id!r}, "
        f"got {control.get('listingId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

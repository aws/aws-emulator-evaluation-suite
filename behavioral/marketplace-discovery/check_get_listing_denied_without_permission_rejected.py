"""get-listing-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-listing-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-discovery"]


@tags("axis:rejection", "cap:c5", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal with an explicit Allow on aws-marketplace:GetListing succeeds; adding an explicit Deny
    makes the same call fail AccessDeniedException with the exact explicit-deny message while the default
    caller still reads that listing, and removing the Deny restores the call."""
    md = ctx.client("marketplace-discovery")
    iam = ctx.client("iam")

    resp = md.search_listings(maxResults=1)
    if not resp["listingSummaries"]:
        raise AssertionError("no listings are visible via SearchListings for this caller/catalog")
    listing_id = resp["listingSummaries"][0]["listingId"]

    user_name = ctx.unique_name("sim2real-marketplace-deny-")
    allow_policy_name = "allow-get-listing"
    deny_policy_name = "deny-get-listing"

    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    allow_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "aws-marketplace:GetListing", "Resource": "*"}
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName=allow_policy_name, PolicyDocument=json.dumps(allow_doc)
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName=allow_policy_name)
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    as_user = ctx.client(
        "marketplace-discovery",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    # Positive control, same identity, before any Deny exists: the explicit Allow must actually
    # grant the real signed call, not just an inert stored document -- and this is what tells "the
    # explicit Deny did it" apart from "a fresh principal has no permissions", since a policyless
    # user is refused here too.
    before = _poll(
        lambda: _error_code(lambda: as_user.get_listing(listingId=listing_id)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90.0,
        interval_s=3.0,
        description="the explicit Allow taking effect on GetListing",
    )
    assert before == "UNEXPECTED_SUCCESS", (
        f"the explicit Allow must grant GetListing on a real signed call before any Deny exists; "
        f"got {before!r}"
    )

    deny_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "aws-marketplace:GetListing", "Resource": "*"}
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName=deny_policy_name, PolicyDocument=json.dumps(deny_doc)
    )
    ctx.on_cleanup(lambda: _drop_deny_policy(iam, user_name, deny_policy_name))

    # IAM changes (new policy) are eventually consistent -- poll for the Deny to actually take
    # effect rather than asserting immediately.
    error = _poll(
        lambda: _error(lambda: as_user.get_listing(listingId=listing_id)),
        lambda e: e.get("Code") == "AccessDeniedException",
        timeout_s=90.0,
        interval_s=3.0,
        description="the explicit Deny overriding the Allow on GetListing",
    )
    assert error.get("Code") == "AccessDeniedException", f"expected AccessDeniedException, got {error!r}"
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"aws-marketplace:GetListing on resource: "
        f"arn:aws:aws-marketplace:::catalog/AWSMarketplace/listing/{listing_id} "
        f"with an explicit deny in an identity-based policy"
    )
    assert error.get("Message") == expected_message, (
        f"expected the explicit-deny message {expected_message!r}, got {error.get('Message')!r}"
    )

    # positive control: the default (undenied) principal still succeeds against
    # the exact same listingId, while the Deny is in effect.
    control = md.get_listing(listingId=listing_id)
    assert control["listingId"] == listing_id

    # Restore: remove ONLY the Deny (the Allow stays attached) and demand the identical call
    # recovers for the SAME principal -- this is what proves the denial was the Deny's doing,
    # not some other account-wide restriction or the Allow having lapsed.
    iam.delete_user_policy(UserName=user_name, PolicyName=deny_policy_name)
    restored = _poll(
        lambda: _error_code(lambda: as_user.get_listing(listingId=listing_id)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90.0,
        interval_s=3.0,
        description="GetListing recovering for the same principal once the Deny is removed",
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        f"removing the Deny must restore the identical GetListing call for the same principal "
        f"while the Allow is still attached; got {restored!r}"
    )


def _error(fn):
    """The captured AWS Error dict, or a sentinel code that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    return {"Code": "UNEXPECTED_SUCCESS"}


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    return _error(fn).get("Code")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _drop_deny_policy(iam, user_name, policy_name):
    """Teardown-only: the body deletes this policy as its restore leg, so tolerate it already
    being gone."""
    try:
        iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

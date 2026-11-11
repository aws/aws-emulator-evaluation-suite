"""deep-s3-immutability-requester-pays-anonymous-with-payer-header-rejected."""

from __future__ import annotations

import itertools
import json
import secrets
import time

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-requester-pays-anonymous-with-payer-header-rejected"
GROUP = 'requester-pays-rejection'
SERVICES = ['s3']

_BODY = b"public-dataset-bytes"
_KEY = "dataset.bin"
_CONVERGE_S = 60.0
_ANON_SEQ = itertools.count(1)


def _delete_bucket(client, bucket):
    """Delete every version and marker, then the bucket."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-imm-")
    params = {"Bucket": name}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _anon_client(ctx, referer):
    """A fresh UNSIGNED S3 client against the same target as ctx.client("s3"), sending `referer`.

    Fresh per attempt because a kept-alive connection can keep observing a superseded
    RequestPayment value; the distinct user-agent suffix makes ctx.client build a new client."""
    anon = ctx.client("s3", config=Config(
        signature_version=UNSIGNED, retries={"max_attempts": 5, "mode": "standard"},
        user_agent_extra=f"sim2real-anon/{next(_ANON_SEQ)}",
    ))

    def _add_referer(request, **_):
        request.headers["Referer"] = referer

    anon.meta.events.register("before-sign.s3", _add_referer)
    return anon


def _anon_get(ctx, bucket, referer):
    """Anonymous GET WITH x-amz-request-payer: return the body bytes, or the (code, message)."""
    try:
        return _anon_client(ctx, referer).get_object(Bucket=bucket, Key=_KEY, RequestPayer="requester")[
            "Body"
        ].read()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _poll(probe, done, description):
    """Poll for a convergence and assert it ARRIVES, never how fast."""
    deadline = time.monotonic() + _CONVERGE_S
    last = probe()
    while not done(last):
        assert time.monotonic() < deadline, (
            f"{description} not observed within {_CONVERGE_S}s; last saw {last!r}"
        )
        time.sleep(2.0)
        last = probe()
    return last


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """On a Requester-Pays bucket an unsigned GetObject with x-amz-request-payer fails with AccessDenied
    and S3's exact anonymous-requester message, while the same request (allowed by a secret-Referer
    grant) returns the bytes under Payer=BucketOwner before and after."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY)

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )
    # Only requests carrying this per-run secret as Referer may read the object.
    referer = secrets.token_urlsafe(32)
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadForRequesterPaysProbe", "Effect": "Allow", "Principal": "*",
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{_KEY}",
            "Condition": {"StringEquals": {"aws:Referer": referer}},
        }],
    }))
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))

    # --- Positive control first: Payer=BucketOwner (the default), the anonymous GET with the
    # header returns the bytes once the public policy is in effect.
    assert s3.get_bucket_request_payment(Bucket=bucket)["Payer"] == "BucketOwner", (
        "a new bucket's Payer is not the default BucketOwner"
    )
    got = _poll(lambda: _anon_get(ctx, bucket, referer), lambda r: r == _BODY,
                "anonymous GET succeeding under Payer=BucketOwner with a public-read policy")
    assert got == _BODY, f"anonymous GET under BucketOwner returned {got!r}"

    # --- Break one thing: Payer=Requester. The same anonymous request, header included, is refused.
    s3.put_bucket_request_payment(
        Bucket=bucket, RequestPaymentConfiguration={"Payer": "Requester"}
    )
    ctx.on_cleanup(lambda: s3.put_bucket_request_payment(
        Bucket=bucket, RequestPaymentConfiguration={"Payer": "BucketOwner"}
    ))
    assert s3.get_bucket_request_payment(Bucket=bucket)["Payer"] == "Requester", (
        "PutBucketRequestPayment(Requester) did not read back"
    )
    refused = _poll(lambda: _anon_get(ctx, bucket, referer), lambda r: not isinstance(r, bytes),
                    "anonymous GET refused on a Requester-Pays bucket")
    assert refused == ("AccessDenied", "Anonymous users cannot invoke requests against Requester Pays buckets. Please authenticate."), (
        f"expected AccessDenied for an anonymous GET with x-amz-request-payer on a Requester-Pays "
        f"bucket, got {refused!r}"
    )

    # The owner is exempt: it reads the same object WITHOUT the header.
    owner = s3.get_object(Bucket=bucket, Key=_KEY)["Body"].read()
    assert owner == _BODY, f"the bucket owner's header-less GET returned {owner!r}"

    # --- Restore the one thing: the identical anonymous request succeeds again.
    s3.put_bucket_request_payment(
        Bucket=bucket, RequestPaymentConfiguration={"Payer": "BucketOwner"}
    )
    again = _poll(lambda: _anon_get(ctx, bucket, referer), lambda r: r == _BODY,
                  "anonymous GET succeeding again after Payer reverted to BucketOwner")
    assert again == _BODY, f"anonymous GET after the revert returned {again!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

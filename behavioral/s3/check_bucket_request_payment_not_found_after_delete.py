"""bucket-request-payment-not-found-after-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-request-payment-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBucketRequestPayment and PutBucketRequestPayment both reject a deleted bucket with
    NoSuchBucket, after succeeding against that same bucket while it existed."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-reqpay-del-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    deleted = False
    ctx.on_cleanup(lambda: None if deleted else s3.delete_bucket(Bucket=name))

    # positive control: both calls succeed while the bucket exists
    s3.put_bucket_request_payment(Bucket=name, RequestPaymentConfiguration={"Payer": "Requester"})
    before = s3.get_bucket_request_payment(Bucket=name)
    assert before["Payer"] == "Requester", f"expected Payer Requester before delete, got {before!r}"

    s3.delete_bucket(Bucket=name)
    deleted = True

    code, message = _client_error(lambda: s3.get_bucket_request_payment(Bucket=name))
    assert code == "NoSuchBucket", f"expected NoSuchBucket from GetBucketRequestPayment, got {code!r}"
    assert message == "The specified bucket does not exist", f"unexpected message {message!r}"

    code2, message2 = _client_error(
        lambda: s3.put_bucket_request_payment(
            Bucket=name, RequestPaymentConfiguration={"Payer": "BucketOwner"}
        )
    )
    assert code2 == "NoSuchBucket", f"expected NoSuchBucket from PutBucketRequestPayment, got {code2!r}"
    assert message2 == "The specified bucket does not exist", f"unexpected message {message2!r}"


def _client_error(fn):
    """The botocore (Error.Code, Error.Message) of fn(); RAISES if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""bucket-request-payment-invalid-payer-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-request-payment-invalid-payer-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketRequestPayment rejects a Payer outside Requester/BucketOwner with MalformedXML,
    leaving the bucket's existing Payer setting unchanged."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    # positive control: a legal Payer value is accepted and reflected back
    s3.put_bucket_request_payment(Bucket=bucket, RequestPaymentConfiguration={"Payer": "Requester"})
    before = s3.get_bucket_request_payment(Bucket=bucket)
    assert before["Payer"] == "Requester", f"expected Payer Requester after a legal put, got {before!r}"

    code, message = _client_error(
        lambda: s3.put_bucket_request_payment(
            Bucket=bucket, RequestPaymentConfiguration={"Payer": "Owner"}
        )
    )
    assert code == "MalformedXML", f"expected MalformedXML, got {code!r}"
    assert message == (
        "The XML you provided was not well-formed or did not validate against our published schema"
    ), f"unexpected message {message!r}"

    after = s3.get_bucket_request_payment(Bucket=bucket)
    assert after["Payer"] == "Requester", (
        f"the rejected put must leave the prior Payer setting intact, got {after!r}"
    )


def _client_error(fn):
    """The botocore (Error.Code, Error.Message) of fn(); RAISES if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-reqpay-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

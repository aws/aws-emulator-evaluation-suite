"""put-bucket-cors-over-100-rules-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-bucket-cors-over-100-rules-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _rules(count: int) -> list:
    return [
        {"AllowedMethods": ["GET"], "AllowedOrigins": [f"https://rule{i}.example.com"]}
        for i in range(count)
    ]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketCors with 101 rules is rejected; the documented ceiling of 100 rules is
    accepted and reads back in full through GetBucketCors."""
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-corslimit-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    code, message = _error(
        lambda: s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": _rules(101)})
    )
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}: {message!r}"
    assert message == "The number of CORS rules should not exceed allowed limit of 100 rules.", (
        f"unexpected message {message!r}"
    )

    # effect absent: the rejected PUT never set a CORS configuration on the bucket
    absent_code, absent_message = _error(lambda: s3.get_bucket_cors(Bucket=bucket))
    assert absent_code == "NoSuchCORSConfiguration", (
        f"expected NoSuchCORSConfiguration, got {absent_code!r}: {absent_message!r}"
    )

    # positive control: the documented ceiling of exactly 100 rules is accepted in full
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": _rules(100)})
    got = s3.get_bucket_cors(Bucket=bucket)["CORSRules"]
    assert len(got) == 100, f"expected 100 rules to read back, got {len(got)}"
    origins = {rule["AllowedOrigins"][0] for rule in got}
    assert origins == {f"https://rule{i}.example.com" for i in range(100)}, (
        f"expected all 100 distinct origins to round-trip, got {sorted(origins)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

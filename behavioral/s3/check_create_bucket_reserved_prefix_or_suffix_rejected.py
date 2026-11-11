"""create-bucket-reserved-prefix-or-suffix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError, EndpointResolutionError

from behavioral_harness import tags

CHECK = "create-bucket-reserved-prefix-or-suffix-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3"]

_STARTS_RESERVED = "The requested bucket name starts with a reserved prefix"
_ENDS_RESERVED = "The requested bucket name ends with a reserved suffix"
_NOT_VALID = "The specified bucket is not valid."
_MALFORMED_XML = (
    "The XML you provided was not well-formed or did not validate against our published schema"
)


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_bucket(client, bucket):
    """Teardown: empty then delete. Tolerates only signals that no general-purpose bucket by this
    name was ever created: not-found, or the SDK reinterpreting a reserved suffix as an access
    point alias (InvalidAccessPointAlias) or a shape it cannot resolve at all
    (EndpointResolutionError, for the directory-bucket --x-s3 suffix)."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except EndpointResolutionError:
        return
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("NoSuchBucket", "InvalidBucketName", "InvalidAccessPointAlias"):
            raise


def _bucket_params(ctx, name: str) -> dict:
    params: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return params


def _assert_invalid_name(ctx, s3, name: str, reason: str) -> None:
    # Only does anything if the create below unexpectedly lands.
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    code, message = _error(lambda: s3.create_bucket(**_bucket_params(ctx, name)))
    assert code == "InvalidBucketName", f"{reason}: expected InvalidBucketName, got {code!r} ({message!r})"
    assert message == _NOT_VALID, f"{reason}: expected the exact message, got {message!r}"


def _assert_reserved_prefix(ctx, s3, name: str, reason: str) -> None:
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    code, message = _error(lambda: s3.create_bucket(**_bucket_params(ctx, name)))
    assert code == "AccessDenied", f"{reason}: expected AccessDenied, got {code!r} ({message!r})"
    assert message == _STARTS_RESERVED, f"{reason}: expected the exact message, got {message!r}"


def _assert_reserved_suffix(ctx, s3, name: str, reason: str) -> None:
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    code, message = _error(lambda: s3.create_bucket(**_bucket_params(ctx, name)))
    assert code == "AccessDenied", f"{reason}: expected AccessDenied, got {code!r} ({message!r})"
    assert message == _ENDS_RESERVED, f"{reason}: expected the exact message, got {message!r}"


def _assert_malformed_xml(ctx, s3, name: str, reason: str) -> None:
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    # The general-purpose body is sent in every region, us-east-1 included, so the request shape
    # does not depend on the region.
    params = {"Bucket": name, "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    code, message = _error(lambda: s3.create_bucket(**params))
    assert code == "MalformedXML", f"{reason}: expected MalformedXML, got {code!r} ({message!r})"
    assert message == _MALFORMED_XML, f"{reason}: expected the exact message, got {message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBucket refuses a name under a reserved prefix or suffix, or with a leading or
    trailing hyphen, naming each refusal's own exact code and message; a valid name is created
    and is the only bucket listed under its prefix.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    s3 = ctx.client("s3")

    base = ctx.unique_name("sim2real-behav-s3rsv-")
    s3.create_bucket(**_bucket_params(ctx, base))
    ctx.on_cleanup(lambda: _delete_bucket(s3, base))
    s3.put_bucket_tagging(Bucket=base, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.head_bucket(Bucket=base)  # independent read: the control bucket really exists

    # The xn-- prefix, and a leading or trailing hyphen, read as a structurally invalid name.
    _assert_invalid_name(ctx, s3, f"xn--{base}", "an xn-- prefix")
    _assert_invalid_name(ctx, s3, f"-{base}", "a leading hyphen")
    _assert_invalid_name(ctx, s3, f"{base}-", "a trailing hyphen")

    # sthree- and amzn-s3-demo- are reserved prefixes, refused as a posture decision (AccessDenied),
    # not a naming-shape decision.
    _assert_reserved_prefix(ctx, s3, f"sthree-{base}", "an sthree- prefix")
    _assert_reserved_prefix(ctx, s3, f"amzn-s3-demo-{base}", "an amzn-s3-demo- prefix")

    # -s3alias, --ol-s3 and .mrap are reserved suffixes (access point, Object Lambda and
    # Multi-Region Access Point aliases), also refused as AccessDenied.
    _assert_reserved_suffix(ctx, s3, f"{base}-s3alias", "a -s3alias suffix")
    _assert_reserved_suffix(ctx, s3, f"{base}--ol-s3", "a --ol-s3 suffix")
    _assert_reserved_suffix(ctx, s3, f"{base}.mrap", "a .mrap suffix")

    # --x-s3 names a directory bucket; sending the general-purpose CreateBucketConfiguration body
    # for that name shape is refused as a schema mismatch, not a naming-shape decision.
    _assert_malformed_xml(ctx, s3, f"{base}--x-s3", "a --x-s3 suffix")

    # Effect absent: the suffixed names share the control's prefix, so a listing under it reads
    # the control alone; each prefixed name is listed under its own prefix and reads nothing.
    names = _list_bucket_names(s3, base)
    assert names == [base], f"ListBuckets under the control's prefix read {names!r}, expected only it"
    for prefixed in (f"xn--{base}", f"-{base}", f"sthree-{base}", f"amzn-s3-demo-{base}"):
        names = _list_bucket_names(s3, prefixed)
        assert names == [], f"ListBuckets under the refused name {prefixed!r} read {names!r}"


def _list_bucket_names(s3, prefix: str) -> list[str]:
    """Every bucket name ListBuckets returns under ``prefix``, paginated."""
    return [
        b["Name"]
        for page in s3.get_paginator("list_buckets").paginate(Prefix=prefix)
        for b in page.get("Buckets", [])
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

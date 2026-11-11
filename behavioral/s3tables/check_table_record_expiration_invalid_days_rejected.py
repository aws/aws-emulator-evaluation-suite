"""table-record-expiration-invalid-days-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-record-expiration-invalid-days-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

NOT_ALLOWED_MSG = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a customer-created table, PutTableRecordExpirationConfiguration with days=2147483648 (one past the
    int32 maximum) answers the same MethodNotAllowedException as days=30, so table eligibility is checked
    first; the get answers MethodNotAllowedException too."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    namespace = _create_namespace(ctx, bucket_arn)
    table_arn, table_name = _create_table(ctx, bucket_arn, namespace)

    # positive control: account/creds are healthy and the table is otherwise usable
    described = s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert described["tableARN"] == table_arn

    # the malformed value: one past the documented int32 maximum of 2147483647.
    # botocore places no client-side upper bound on this field, so this genuinely
    # reaches the service instead of being rejected by the SDK before the network call.
    invalid_code, invalid_msg = _error(
        lambda: s3tables.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"status": "enabled", "settings": {"days": 2147483648}}
        )
    )
    assert invalid_code == "MethodNotAllowedException", (
        f"expected the eligibility gate (MethodNotAllowedException) to precede days "
        f"validation on an ineligible table, got {invalid_code!r}"
    )
    assert invalid_msg == NOT_ALLOWED_MSG, invalid_msg

    # a well-formed value on the same ineligible table must fail with the identical
    # code -- proving the rejection is the table-eligibility gate, not a days-range
    # check that happens to also catch the out-of-range value
    valid_code, valid_msg = _error(
        lambda: s3tables.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"status": "enabled", "settings": {"days": 30}}
        )
    )
    assert (valid_code, valid_msg) == (invalid_code, invalid_msg), (
        f"invalid days got {(invalid_code, invalid_msg)!r} but a well-formed value got "
        f"{(valid_code, valid_msg)!r} on the same table -- these must be the same gate"
    )

    # effect absent: neither rejected attempt persisted a configuration
    get_code, get_msg = _error(
        lambda: s3tables.get_table_record_expiration_configuration(tableArn=table_arn)
    )
    assert get_code == "MethodNotAllowedException", f"expected MethodNotAllowedException, got {get_code!r}"
    assert get_msg == NOT_ALLOWED_MSG, get_msg


def _create_table_bucket(ctx):
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-recexp-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn):
    s3tables = ctx.client("s3tables")
    namespace = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace))
    return namespace


def _create_table(ctx, bucket_arn, namespace):
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return resp["tableARN"], name


def _error(fn) -> tuple[str, str]:
    """Call fn() expecting a refusal; return (code, message). An unexpected
    success raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""record-de-aggregation-json-splits-one-put-across-jq-derived-prefixes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "record-de-aggregation-json-splits-one-put-across-jq-derived-prefixes"
GROUP = "partitioning"
SERVICES = ["firehose"]

_SUBRECORDS = 4
_TENANTS = ["alpha", "bravo", "charlie", "delta"]

# 64 MiB is the floor when dynamic partitioning is on, so the 60 s interval is what
# actually fires for four small sub-records.
_BUFFER = {"SizeInMBs": 64, "IntervalInSeconds": 60}
_DELIVERY_BUDGET_S = 480.0  # dynamic-partitioning delivery can take up to ~420 s
_POLL_INTERVAL_S = 10.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0

_METADATA_PROCESSOR = {
    "Type": "MetadataExtraction",
    "Parameters": [
        {"ParameterName": "MetadataExtractionQuery", "ParameterValue": "{tenant:.tenant}"},
        {"ParameterName": "JsonParsingEngine", "ParameterValue": "JQ-1.6"},
    ],
}
_DEAGGREGATION_PROCESSOR = {
    "Type": "RecordDeAggregation",
    "Parameters": [{"ParameterName": "SubRecordType", "ParameterValue": "JSON"}],
}


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """One aggregated PutRecord is split into four sub-records, each under its own jq-derived
    prefix; a control stream without RecordDeAggregation does not produce that split.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    assert len(_TENANTS) == _SUBRECORDS, (
        f"the check is misconfigured: {len(_TENANTS)} tenants for {_SUBRECORDS} sub-records"
    )

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)

    treated = _create_stream(ctx, bucket, role_arn, "deagg", deaggregate=True)
    control = _create_stream(ctx, bucket, role_arn, "noagg", deaggregate=False)

    treated_desc = _wait_active(ctx, treated)
    _wait_active(ctx, control)

    # The described processor order is the transformation order.
    processing = treated_desc["Destinations"][0]["ExtendedS3DestinationDescription"][
        "ProcessingConfiguration"
    ]
    assert processing["Enabled"] is True, (
        f"the treated stream reports ProcessingConfiguration.Enabled {processing['Enabled']!r}"
    )
    assert [p["Type"] for p in processing["Processors"]] == [
        "RecordDeAggregation",
        "MetadataExtraction",
    ], (
        f"the treated stream's processors are {[p['Type'] for p in processing['Processors']]!r}; "
        f"the list order is the transformation order and RecordDeAggregation must precede "
        f"MetadataExtraction or the jq query sees the whole aggregate"
    )
    assert processing["Processors"][0]["Parameters"] == [
        {"ParameterName": "SubRecordType", "ParameterValue": "JSON"}
    ], (
        f"the RecordDeAggregation processor's parameters came back "
        f"{processing['Processors'][0]['Parameters']!r}, expected SubRecordType=JSON"
    )

    markers = {t: ctx.unique_name(f"deagg-{t}-") for t in _TENANTS}
    aggregated = "".join(
        json.dumps({"tenant": t, "marker": markers[t]}, sort_keys=True) + "\n"
        for t in _TENANTS
    ).encode()

    for leg, stream in (("treated", treated), ("control", control)):
        resp = firehose.put_record(DeliveryStreamName=stream, Record={"Data": aggregated})
        assert resp["RecordId"], (
            f"PutRecord on the {leg} leg returned an empty RecordId: {resp!r}"
        )

    want = {f"deagg/{t}/" for t in _TENANTS}

    # The routing decision is observable only in the keys Firehose chose.
    keys = _poll_until(
        lambda: _all_keys(ctx, bucket, "deagg/"),
        lambda ks: _prefixes(ks, "deagg/") >= want,
        budget_s=_DELIVERY_BUDGET_S,
        description=(
            f"all {_SUBRECORDS} deaggregated prefixes {sorted(want)!r} appear under "
            f"s3://{bucket}/deagg/"
        ),
    )
    got = _prefixes(keys, "deagg/")
    assert got == want, (
        f"the deaggregating leg delivered prefixes {sorted(got)!r}, expected exactly "
        f"{sorted(want)!r}. One PutRecord carrying {_SUBRECORDS} newline-delimited JSON "
        f"objects must be split into {_SUBRECORDS} sub-records, each partitioned by its own "
        f"`tenant`. Keys: {keys!r}"
    )
    assert not [k for k in keys if "!{" in k], (
        f"an unresolved partition-key expression was used as a literal key: {sorted(keys)!r}"
    )

    per_prefix: dict[str, list[str]] = {}
    for key in keys:
        raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        prefix = key[: key.index("/", len("deagg/")) + 1]
        per_prefix.setdefault(prefix, []).extend(
            json.loads(line)["marker"] for line in raw.splitlines() if line.strip()
        )
    expected = {f"deagg/{t}/": [markers[t]] for t in _TENANTS}
    assert per_prefix == expected, (
        f"the sub-records were mis-routed: {per_prefix!r}, expected {expected!r}. Each "
        f"sub-record must land under the prefix named by its OWN tenant and nowhere else"
    )

    treated_errors = _all_keys(ctx, bucket, "deagg-err/")
    assert treated_errors == [], (
        f"the deaggregating leg wrote {len(treated_errors)} objects under its "
        f"ErrorOutputPrefix: {treated_errors!r}. All {_SUBRECORDS} sub-records carry a "
        f"`tenant` field, so none may fail metadata extraction"
    )

    # Without deaggregation the blob may route to one prefix or fail metadata extraction, so
    # only "not split" is asserted. Requiring some object stops a target with no delivery
    # path from passing by delivering nothing.
    control_any = _poll_until(
        lambda: _all_keys(ctx, bucket, "noagg/") + _all_keys(ctx, bucket, "noagg-err/"),
        lambda ks: len(ks) > 0,
        budget_s=_DELIVERY_BUDGET_S,
        description=(
            f"the non-deaggregating control leg delivers at least one object under "
            f"s3://{bucket}/noagg/ or s3://{bucket}/noagg-err/"
        ),
    )
    control_data = _all_keys(ctx, bucket, "noagg/")
    control_prefixes = _prefixes(control_data, "noagg/")
    control_want = {f"noagg/{t}/" for t in _TENANTS}
    assert control_prefixes != control_want, (
        f"the control leg -- which declares NO RecordDeAggregation processor -- also split the "
        f"single aggregated record into all {_SUBRECORDS} tenant prefixes "
        f"{sorted(control_prefixes)!r}. Deaggregation must be opt in; a target that always "
        f"splits makes the treated leg's result meaningless. Control objects: {control_any!r}"
    )




def _prefixes(keys: list[str], root: str) -> set[str]:
    out = set()
    for key in keys:
        idx = key.find("/", len(root))
        assert idx != -1, (
            f"delivered key {key!r} has no partition segment under {root!r}; the "
            f"!{{partitionKeyFromQuery:...}} expression did not expand into a directory level"
        )
        out.add(key[: idx + 1])
    return out


def _poll_until(probe, predicate, *, budget_s: float, description: str):
    """Poll until predicate holds; RAISE on timeout, never return the last value."""
    end = time.monotonic() + budget_s
    last = None
    while time.monotonic() < end:
        last = probe()
        if predicate(last):
            return last
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"DATAPLANE_UNIMPLEMENTED?: {description} did not happen within {budget_s}s. Last "
        f"observation: {last!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-deagg-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Bounded at 40 s because all of a check's cleanups share a 60 s budget."""
    s3 = ctx.client("s3")
    end = time.monotonic() + 40.0
    while time.monotonic() < end:
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            if not resp.get("IsTruncated"):
                break
            token = resp["NextContinuationToken"]
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "BucketNotEmpty":
                raise
            time.sleep(4.0)
    raise AssertionError(f"bucket {bucket!r} could not be emptied and deleted within 40s")


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-deagg-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description=f"sim2real-behav {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:AbortMultipartUpload",
                            "s3:GetBucketLocation",
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:ListBucketMultipartUploads",
                            "s3:PutObject",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket}",
                            f"arn:aws:s3:::{bucket}/*",
                        ],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="s3-write"))
    return arn


def _create_stream(ctx, bucket: str, role_arn: str, leg: str, *, deaggregate: bool) -> str:
    """Bounded retry past the transient InvalidArgumentException a freshly created,
    eventually consistent delivery role produces. Raises on exhaustion."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name(f"sim2real-fh-{leg}-")
    processors = (
        [dict(_DEAGGREGATION_PROCESSOR), dict(_METADATA_PROCESSOR)]
        if deaggregate
        else [dict(_METADATA_PROCESSOR)]
    )
    end = time.monotonic() + _CREATE_BUDGET_S
    last = None
    while time.monotonic() < end:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "Prefix": f"{leg}/!{{partitionKeyFromQuery:tenant}}/",
                    "ErrorOutputPrefix": f"{leg}-err/!{{firehose:error-output-type}}/",
                    "BufferingHints": dict(_BUFFER),
                    "CompressionFormat": "UNCOMPRESSED",
                    "DynamicPartitioningConfiguration": {"Enabled": True},
                    "ProcessingConfiguration": {"Enabled": True, "Processors": processors},
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(
                lambda n=name: firehose.delete_delivery_stream(
                    DeliveryStreamName=n, AllowForceDelete=True
                )
            )
            return name
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(5.0)
    raise AssertionError(
        f"CreateDeliveryStream({name!r}, deaggregate={deaggregate}) never succeeded within "
        f"{_CREATE_BUDGET_S}s; last error {last}"
    )


def _wait_active(ctx, name: str) -> dict:
    firehose = ctx.client("firehose")
    end = time.monotonic() + _ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < end:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        assert status in ("CREATING", "UPDATING"), (
            f"delivery stream {name!r} reported status {status!r} while waiting for ACTIVE"
        )
        time.sleep(4.0)
    raise AssertionError(
        f"delivery stream {name!r} never became ACTIVE within {_ACTIVE_BUDGET_S}s (last "
        f"status {status!r})"
    )


def _all_keys(ctx, bucket: str, prefix: str) -> list[str]:
    s3 = ctx.client("s3")
    out: list[str] = []
    token = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        out.extend(o["Key"] for o in resp.get("Contents", []))
        if not resp.get("IsTruncated"):
            return sorted(out)
        token = resp["NextContinuationToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

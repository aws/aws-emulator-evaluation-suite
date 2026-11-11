"""bucket-replication-destination-validation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-replication-destination-validation-rejected"
GROUP = "replication"
SERVICES = ["s3"]

_ROLE_PROPAGATION_CODES = ("AccessDenied", "MalformedPolicy")


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the run's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _retry_while_role_propagates(ctx, probe, cap_s: float = 60.0, interval_s: float = 3.0):
    """Call probe() (an (code, message) pair) until it stops answering with a freshly-created-role
    propagation symptom; still answering one at the deadline raises TimeoutError."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = probe()
        if code not in _ROLE_PROPAGATION_CODES:
            return code, message
        if time.monotonic() + interval_s >= deadline:
            raise TimeoutError(
                f"the role had not propagated within {timeout_s:.0f}s: {code!r} {message!r}"
            )
        time.sleep(interval_s)


def _retry_until_accepted(ctx, fn, cap_s: float = 60.0, interval_s: float = 3.0) -> None:
    """Call fn() until it succeeds, retrying only on a role-propagation symptom; any other
    ClientError propagates, and a symptom still answered at the deadline raises TimeoutError."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in _ROLE_PROPAGATION_CODES:
                raise
            if time.monotonic() + interval_s >= deadline:
                raise TimeoutError(
                    f"the role had not propagated within {timeout_s:.0f}s: {exc}"
                ) from exc
            time.sleep(interval_s)


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            to_delete = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            to_delete += [{"Key": m["Key"], "VersionId": m["VersionId"]} for m in page.get("DeleteMarkers", [])]
            if to_delete:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": to_delete}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_replication_role(ctx, iam, src: str, dst: str) -> str:
    """Create a minimal IAM role S3 can assume for cross-bucket replication, scoped to the two
    buckets. Returns the role ARN; teardown registered."""
    role_name = ctx.unique_name("sim2real-behav-replval-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = "replication-policy"
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{src}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObjectVersionForReplication"],
                "Resource": f"arn:aws:s3:::{src}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete"],
                "Resource": f"arn:aws:s3:::{dst}/*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    return role_arn


def _get_replication(fn):
    """GetBucketReplication returning None when no configuration exists, raising on any other
    error."""
    try:
        return fn()["ReplicationConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError":
            return None
        raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketReplication rejects ReplicationTime without Metrics, duplicate rule Priority, and
    Filter without DeleteMarkerReplication, each with its exact message and no partial effect.
    A fully valid rule is accepted, and Metrics without ReplicationTime is accepted too."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    src = ctx.unique_name("sim2real-behav-replval-src-")
    dst = ctx.unique_name("sim2real-behav-replval-dst-")
    _create_bucket(ctx, s3, src)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src))
    _create_bucket(ctx, s3, dst)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, dst))
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=dst, VersioningConfiguration={"Status": "Enabled"})
    dst_arn = f"arn:aws:s3:::{dst}"

    role_arn = _create_replication_role(ctx, iam, src, dst)

    def put(rules):
        s3.put_bucket_replication(Bucket=src, ReplicationConfiguration={"Role": role_arn, "Rules": rules})

    # ---- 1. ReplicationTime without Metrics is refused ----
    rule_rt_only = {
        "ID": "rt-no-metrics",
        "Status": "Enabled",
        "Priority": 1,
        "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": dst_arn, "ReplicationTime": {"Status": "Enabled", "Time": {"Minutes": 15}}},
    }
    code, message = _retry_while_role_propagates(ctx, lambda: _error(lambda: put([rule_rt_only])))
    assert code == "InvalidRequest", f"expected InvalidRequest for ReplicationTime without Metrics, got {code!r}"
    assert message == "Replication destination must contain both ReplicationTime and Metrics or neither.", message
    assert _get_replication(lambda: s3.get_bucket_replication(Bucket=src)) is None, (
        "a rejected PutBucketReplication must not apply any configuration"
    )

    # ---- 2. Metrics without ReplicationTime is accepted (the pairing rule is one-directional) ----
    rule_metrics_only = {
        "ID": "metrics-no-rt",
        "Status": "Enabled",
        "Priority": 1,
        "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": dst_arn, "Metrics": {"Status": "Enabled"}},
    }
    _retry_until_accepted(ctx, lambda: put([rule_metrics_only]))
    applied = _get_replication(lambda: s3.get_bucket_replication(Bucket=src))
    assert applied is not None, "Metrics without ReplicationTime must be accepted and read back"
    destination = applied["Rules"][0]["Destination"]
    assert destination.get("Metrics", {}).get("Status") == "Enabled", (
        f"expected Metrics.Status 'Enabled', got {destination.get('Metrics')!r}"
    )
    assert "ReplicationTime" not in destination, (
        f"expected no ReplicationTime in a Metrics-only destination, got {destination!r}"
    )
    s3.delete_bucket_replication(Bucket=src)
    assert _get_replication(lambda: s3.get_bucket_replication(Bucket=src)) is None, (
        "DeleteBucketReplication must clear the configuration before the next rule is tried"
    )

    # ---- 3. Two rules with the same Priority are refused ----
    dup_priority = 7
    rule_a = {
        "ID": "dup-a",
        "Status": "Enabled",
        "Priority": dup_priority,
        "Filter": {"Prefix": "a/"},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": dst_arn},
    }
    rule_b = {
        "ID": "dup-b",
        "Status": "Enabled",
        "Priority": dup_priority,
        "Filter": {"Prefix": "b/"},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": dst_arn},
    }
    code2, message2 = _error(lambda: put([rule_a, rule_b]))
    assert code2 == "InvalidRequest", f"expected InvalidRequest for duplicate Priority, got {code2!r}"
    assert message2 == f"Found duplicate priority {dup_priority}.", message2
    assert _get_replication(lambda: s3.get_bucket_replication(Bucket=src)) is None, (
        "a rejected PutBucketReplication must not apply any configuration"
    )

    # ---- 4. A rule using Filter without DeleteMarkerReplication is refused ----
    rule_filter_no_dmr = {
        "ID": "filter-no-dmr",
        "Status": "Enabled",
        "Priority": 1,
        "Filter": {"Prefix": "x/"},
        "Destination": {"Bucket": dst_arn},
    }
    code3, message3 = _error(lambda: put([rule_filter_no_dmr]))
    assert code3 == "InvalidRequest", f"expected InvalidRequest for Filter without DeleteMarkerReplication, got {code3!r}"
    assert message3 == (
        "DeleteMarkerReplication must be specified for this version of Cross Region Replication "
        "configuration schema. Please refer to S3 Developer Guide for more information."
    ), message3
    assert _get_replication(lambda: s3.get_bucket_replication(Bucket=src)) is None, (
        "a rejected PutBucketReplication must not apply any configuration"
    )

    # ---- positive control: a fully valid rule is accepted and read back ----
    rule_valid = {
        "ID": "valid",
        "Status": "Enabled",
        "Priority": 1,
        "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {
            "Bucket": dst_arn,
            "ReplicationTime": {"Status": "Enabled", "Time": {"Minutes": 15}},
            "Metrics": {"Status": "Enabled", "EventThreshold": {"Minutes": 15}},
        },
    }
    put([rule_valid])
    final = _get_replication(lambda: s3.get_bucket_replication(Bucket=src))
    assert final is not None, "a fully valid replication rule must be accepted"
    assert final["Role"] == role_arn, f"expected Role {role_arn}, got {final['Role']}"
    final_dest = final["Rules"][0]["Destination"]
    assert final_dest["Bucket"] == dst_arn, f"expected destination {dst_arn}, got {final_dest['Bucket']}"
    assert final_dest["ReplicationTime"]["Status"] == "Enabled", final_dest
    assert final_dest["Metrics"]["Status"] == "Enabled", final_dest
    assert final_dest["Metrics"]["EventThreshold"]["Minutes"] == 15, final_dest


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

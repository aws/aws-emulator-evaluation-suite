"""replication-covers-the-eligible-prefix-only-and-withholds-the-delete-marker."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-covers-the-eligible-prefix-only-and-withholds-the-delete-marker"
GROUP = "replication"
SERVICES = ["s3"]

_ELIGIBLE = "repl/"
_INELIGIBLE = "keep/"
_LAND_TIMEOUT_S = 420.0
_HOLD_CAP_S = 240.0


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Replication delivers only what a rule selects, and a disabled-marker rule withholds deletes.
    Checks ReplicationStatus COMPLETED/REPLICA, no status on the unmatched object, and a later
    eligible object still replicating.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html
    """
    s3 = ctx.client("s3")
    source = _new_versioned_bucket(ctx, s3)
    dest = _new_versioned_bucket(ctx, s3)
    role_arn = _replication_role(ctx, source, dest)

    config = {
        "Role": role_arn,
        "Rules": [
            {
                "ID": "eligible-prefix-only",
                "Status": "Enabled",
                "Priority": 1,
                "Filter": {"Prefix": _ELIGIBLE},
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Destination": {"Bucket": f"arn:aws:s3:::{dest}"},
            }
        ],
    }
    # The replication role's trust policy takes a few seconds to become visible to S3's replication
    # engine, so PutBucketReplication can transiently refuse a brand-new role.
    _poll_until(
        lambda: _try(lambda: s3.put_bucket_replication(
            Bucket=source, ReplicationConfiguration=config)),
        lambda code: code == _SUCCEEDED,
        timeout_s=120.0,
        interval_s=5.0,
        description="PutBucketReplication to accept the freshly created replication role",
    )
    rules = s3.get_bucket_replication(Bucket=source)["ReplicationConfiguration"]["Rules"]
    assert [r["Filter"]["Prefix"] for r in rules] == [_ELIGIBLE], (
        f"GetBucketReplication reports filters {[r.get('Filter') for r in rules]}; expected exactly "
        f"one rule filtered on prefix {_ELIGIBLE!r}"
    )

    eligible_key = f"{_ELIGIBLE}first.bin"
    ineligible_key = f"{_INELIGIBLE}first.bin"
    eligible_body = b"eligible-payload-" + b"E" * 512
    ineligible_body = b"ineligible-payload-" + b"I" * 512
    s3.put_object(Bucket=source, Key=eligible_key, Body=eligible_body)
    s3.put_object(Bucket=source, Key=ineligible_key, Body=ineligible_body)

    # --- Control: the eligible object lands in the destination, and L is its measured latency.
    started = time.monotonic()
    _poll_until(
        lambda: _try(lambda: s3.head_object(Bucket=dest, Key=eligible_key)),
        lambda code: code == _SUCCEEDED,
        timeout_s=_LAND_TIMEOUT_S,
        interval_s=5.0,
        description=f"the eligible object {eligible_key!r} to be replicated into {dest}",
    )
    latency_s = time.monotonic() - started
    # Absences are held for 3x the measured replication latency (min 15s, capped), not a sleep.
    hold_s = min(max(3.0 * latency_s, 15.0), _HOLD_CAP_S)

    replica = s3.get_object(Bucket=dest, Key=eligible_key)["Body"].read()
    assert replica == eligible_body, (
        f"the replica of {eligible_key!r} is {len(replica)} bytes and does not match the "
        f"{len(eligible_body)}-byte source body"
    )

    # --- The replication-status header, on both sides. Nothing is pinned: the values come from the
    # documented vocabulary and the source's own convergence.
    source_status = _poll_until(
        lambda: s3.head_object(Bucket=source, Key=eligible_key).get("ReplicationStatus"),
        lambda status: status == "COMPLETED",
        timeout_s=max(120.0, 2.0 * latency_s),
        interval_s=5.0,
        description=f"the source object {eligible_key!r} to report ReplicationStatus COMPLETED",
    )
    assert source_status == "COMPLETED", (
        f"the source object reports ReplicationStatus {source_status!r}, expected 'COMPLETED'"
    )
    dest_head = s3.head_object(Bucket=dest, Key=eligible_key)
    assert dest_head.get("ReplicationStatus") == "REPLICA", (
        f"the destination object reports ReplicationStatus "
        f"{dest_head.get('ReplicationStatus')!r}, expected 'REPLICA' — a replica that does not "
        "identify itself as one cannot be told apart from a client-side copy"
    )

    # --- Absence 1: the ineligible object was never eligible, so it carries no status at all and
    # never appears at the destination. Held for hold_s, with a second observable.
    source_ineligible = s3.head_object(Bucket=source, Key=ineligible_key)
    assert "ReplicationStatus" not in source_ineligible, (
        f"the source object {ineligible_key!r} — which matches no rule — reports ReplicationStatus "
        f"{source_ineligible.get('ReplicationStatus')!r}; S3 returns that header only for objects "
        "eligible for replication"
    )
    _hold_absent(
        s3,
        dest,
        ineligible_key,
        _INELIGIBLE,
        hold_s,
        reason=(
            f"{ineligible_key!r} matches no replication rule, so it must never reach {dest}; the "
            f"eligible object landed in {latency_s:.1f}s on this same wiring"
        ),
    )

    # --- Absence 2: a delete marker on the source, with DeleteMarkerReplication Disabled, is
    # withheld. The source really is hidden; the replica really is not.
    marker = s3.delete_object(Bucket=source, Key=eligible_key)
    assert marker.get("DeleteMarker") is True, (
        f"deleting {eligible_key!r} on a versioned bucket returned DeleteMarker "
        f"{marker.get('DeleteMarker')!r}; expected True"
    )
    hidden = _error(lambda: s3.get_object(Bucket=source, Key=eligible_key))
    assert hidden == ("NoSuchKey", "The specified key does not exist."), (
        f"{eligible_key!r} is still readable on the SOURCE after its delete marker was created: "
        f"{hidden!r}"
    )
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        held = s3.get_object(Bucket=dest, Key=eligible_key)["Body"].read()
        assert held == eligible_body, (
            f"the replica of {eligible_key!r} changed to {len(held)} bytes while the source's "
            "delete marker was being withheld"
        )
        time.sleep(5.0)
    dest_versions = s3.list_object_versions(Bucket=dest, Prefix=eligible_key)
    assert dest_versions.get("DeleteMarkers", []) == [], (
        f"the destination grew {len(dest_versions.get('DeleteMarkers', []))} delete marker(s) for "
        f"{eligible_key!r} within {hold_s:.0f}s, but the rule sets DeleteMarkerReplication "
        f"Status=Disabled; the eligible object itself replicated in {latency_s:.1f}s, so a "
        "propagated marker would have arrived by now"
    )

    # --- Re-prove delivery: the pipeline is still alive, so neither absence above was "nothing is
    # replicating any more".
    second_key = f"{_ELIGIBLE}second.bin"
    second_body = b"second-eligible-payload-" + b"S" * 512
    s3.put_object(Bucket=source, Key=second_key, Body=second_body)
    _poll_until(
        lambda: _try(lambda: s3.head_object(Bucket=dest, Key=second_key)),
        lambda code: code == _SUCCEEDED,
        timeout_s=max(180.0, 4.0 * latency_s),
        interval_s=5.0,
        description=(
            f"a second eligible object {second_key!r} to replicate, proving the pipeline was live "
            "throughout both absence windows"
        ),
    )
    assert s3.get_object(Bucket=dest, Key=second_key)["Body"].read() == second_body, (
        f"the replica of {second_key!r} does not match its source body"
    )




def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it. TEARDOWN ONLY —
    never on an assertion path."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_versioned_bucket(ctx, s3):
    """Create a uniquely-named, tagged, versioning-enabled bucket with teardown registered."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _replication_role(ctx, source: str, dest: str) -> str:
    """Create (in-check, tagged) the IAM role S3's replication engine assumes; return its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-repl-role-")
    policy_name = "sim2real-behav-replication-policy"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:check", "Value": CHECK}],
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{source}"],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObjectVersionForReplication",
                        "s3:GetObjectVersionAcl",
                        "s3:GetObjectVersionTagging",
                    ],
                    "Resource": [f"arn:aws:s3:::{source}/*"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                    "Resource": [f"arn:aws:s3:::{dest}/*"],
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    return role["Role"]["Arn"]


def _delete_role(iam, role_name: str, policy_name: str) -> None:
    """TEARDOWN ONLY — never on an assertion path."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


_SUCCEEDED = "<call succeeded>"


def _try(fn):
    """The Error.Code of fn(), or _SUCCEEDED (a value no error code equals) when fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "unknown"
    return _SUCCEEDED


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message). RAISES if
    fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to fail and it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); return the result. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s:.0f}s for {description} and it never happened; last observation: "
        f"{last!r}"
    )


def _hold_absent(s3, bucket, key, prefix, hold_s, *, reason):
    """Assert `key` stays absent from `bucket` for hold_s, on TWO observables: a 404 HeadObject and
    an empty listing of `prefix`. Raises the moment either says otherwise."""
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        try:
            s3.head_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            assert status == 404, (
                f"HeadObject on {key!r} in {bucket} failed with HTTP {status} rather than 404 while "
                f"proving absence: {reason}"
            )
        else:
            raise AssertionError(f"{key!r} appeared in {bucket}: {reason}")
        listing = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        assert listing.get("KeyCount", len(listing.get("Contents", []))) == 0, (
            f"{bucket} lists {[o['Key'] for o in listing.get('Contents', [])]} under {prefix!r}: "
            f"{reason}"
        )
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

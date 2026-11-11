"""s3crr-replication-fails-visibly-when-the-role-cannot-write-the-destination."""

from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3crr-replication-fails-visibly-when-the-role-cannot-write-the-destination"
GROUP = "replication"
SERVICES = ["s3"]

#: What _try returns when its call succeeds; no S3 error code can equal it.
_SUCCEEDED = "<the call succeeded>"
_ARRIVAL_TIMEOUT_S = 240.0
_STATUS_TIMEOUT_S = 240.0
_HOLD_FLOOR_S = 25.0
_HOLD_CAP_S = 60.0

_SOURCE_READ_ACTIONS = [
    "s3:GetObjectVersionForReplication",
    "s3:GetObjectVersionAcl",
    "s3:GetObjectVersionTagging",
]
_DEST_WRITE_ACTIONS = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]


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
    """A role denied s3:ReplicateObject yields ReplicationStatus FAILED and delivers nothing.

    An identically wired healthy pair reaches COMPLETED, so FAILED is not a blanket outcome.
    """
    s3 = ctx.client("s3")
    peer = _peer_region(ctx)
    peer_s3 = ctx.client("s3", region=peer)
    partition = _partition(ctx)

    healthy_source = _new_versioned_bucket(ctx, s3, ctx.region, "sim2real-behav-crr-ok-src-")
    healthy_dest = _new_versioned_bucket(ctx, peer_s3, peer, "sim2real-behav-crr-ok-dst-")
    _enable_replication(
        ctx,
        s3,
        healthy_source,
        _rule_set(
            partition,
            healthy_dest,
            _replication_role(
                ctx, partition, healthy_source, healthy_dest, _DEST_WRITE_ACTIONS
            ),
        ),
    )

    broken_source = _new_versioned_bucket(ctx, s3, ctx.region, "sim2real-behav-crr-bad-src-")
    broken_dest = _new_versioned_bucket(ctx, peer_s3, peer, "sim2real-behav-crr-bad-dst-")
    # The one difference: this role may delete and tag at the destination but not WRITE an object
    # there. Everything else — trust policy, source-side reads, rule, region pair — is identical.
    _enable_replication(
        ctx,
        s3,
        broken_source,
        _rule_set(
            partition,
            broken_dest,
            _replication_role(
                ctx,
                partition,
                broken_source,
                broken_dest,
                [a for a in _DEST_WRITE_ACTIONS if a != "s3:ReplicateObject"],
            ),
        ),
    )

    key = "crr/subject.bin"
    healthy_body = (ctx.unique_name("healthy-").encode() + b"-" + bytes(range(256))) * 32
    broken_body = (ctx.unique_name("broken-").encode() + b"-" + bytes(range(256))) * 32
    s3.put_object(Bucket=healthy_source, Key=key, Body=healthy_body)
    s3.put_object(Bucket=broken_source, Key=key, Body=broken_body)

    # --- Positive control: the healthy pair replicates and says COMPLETED.
    started = time.monotonic()
    _poll_until(
        lambda: _try(lambda: peer_s3.head_object(Bucket=healthy_dest, Key=key)),
        lambda code: code == _SUCCEEDED,
        timeout_s=_ARRIVAL_TIMEOUT_S,
        interval_s=5.0,
        description=(
            f"the control object {key!r} to replicate from {healthy_source} into {healthy_dest} "
            f"in {peer}"
        ),
    )
    latency_s = time.monotonic() - started
    # The absence window is sized from the measured delivery latency, clamped, not a fixed sleep.
    hold_s = min(max(2.0 * latency_s, _HOLD_FLOOR_S), _HOLD_CAP_S)
    landed = peer_s3.get_object(Bucket=healthy_dest, Key=key)["Body"].read()
    assert hashlib.sha256(landed).hexdigest() == hashlib.sha256(healthy_body).hexdigest(), (
        f"the control replica in {healthy_dest} is {len(landed)} bytes and does not match its "
        f"{len(healthy_body)}-byte source body"
    )
    healthy_status = _poll_until(
        lambda: s3.head_object(Bucket=healthy_source, Key=key).get("ReplicationStatus"),
        lambda status: status == "COMPLETED",
        timeout_s=_STATUS_TIMEOUT_S,
        interval_s=5.0,
        description=(
            f"the control object in {healthy_source} to report ReplicationStatus COMPLETED (its "
            f"replica was readable in {peer} after {latency_s:.1f}s)"
        ),
    )
    assert healthy_status == "COMPLETED", (
        f"the control object reports ReplicationStatus {healthy_status!r}, expected 'COMPLETED'"
    )

    # --- The broken pair: the source itself admits the replication failed.
    broken_status = _poll_until(
        lambda: s3.head_object(Bucket=broken_source, Key=key).get("ReplicationStatus"),
        lambda status: status == "FAILED",
        timeout_s=_STATUS_TIMEOUT_S,
        interval_s=5.0,
        description=(
            f"the object in {broken_source}, whose role cannot s3:ReplicateObject into "
            f"{broken_dest}, to report ReplicationStatus FAILED (the control pair reached COMPLETED "
            f"on identical wiring in {latency_s:.1f}s)"
        ),
    )
    assert broken_status == "FAILED", (
        f"the object whose replication role cannot write the destination reports ReplicationStatus "
        f"{broken_status!r}, expected 'FAILED' — a status that never reports failure tells an "
        f"operator nothing about unreplicated data"
    )

    # --- And nothing was delivered: two observables, held for a window measured on the control.
    _hold_absent(
        peer_s3,
        broken_dest,
        key,
        "crr/",
        hold_s,
        reason=(
            f"the replication role for {broken_source} is denied s3:ReplicateObject on "
            f"{broken_dest}, and the source object already reports ReplicationStatus FAILED; the "
            f"control pair delivered in {latency_s:.1f}s on identical wiring"
        ),
    )
    still_there = s3.get_object(Bucket=broken_source, Key=key)["Body"].read()
    assert hashlib.sha256(still_there).hexdigest() == hashlib.sha256(broken_body).hexdigest(), (
        f"the source object in {broken_source} is {len(still_there)} bytes after its replication "
        f"failed; a failed replication must not disturb the source"
    )


def _rule_set(partition: str, dest: str, role_arn: str) -> dict:
    """The one-rule replication configuration both pairs use, so only the ROLE differs."""
    return {
        "Role": role_arn,
        "Rules": [
            {
                "ID": "crr-everything",
                "Status": "Enabled",
                "Priority": 1,
                "Filter": {"Prefix": ""},
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Destination": {"Bucket": f"arn:{partition}:s3:::{dest}"},
            }
        ],
    }


def _peer_region(ctx) -> str:
    """A second region DERIVED from this account's enabled regions, never hardcoded.

    Prefers a region sharing ctx.region's geography (so the replication hop stays inside one
    continent) and falls back to the whole enabled set. The chosen region's own opt-in status is
    asserted, because a bucket cannot be created in a region this account has not enabled.
    """
    regions = ctx.client("ec2").describe_regions()["Regions"]
    usable = {
        r["RegionName"]: r.get("OptInStatus")
        for r in regions
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
        and r["RegionName"] != ctx.region
    }
    assert usable, (
        f"DescribeRegions reports no region enabled for this account other than {ctx.region!r} "
        f"(saw {[(r['RegionName'], r.get('OptInStatus')) for r in regions]!r}); cross-region "
        f"replication cannot be established"
    )
    geo = ctx.region.split("-")[0]
    same_geo = sorted(name for name in usable if name.split("-")[0] == geo)
    peer = (same_geo or sorted(usable))[0]
    assert usable[peer] in ("opt-in-not-required", "opted-in"), (
        f"the derived peer region {peer!r} reports OptInStatus {usable[peer]!r}; it must be enabled "
        f"for this account"
    )
    return peer


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


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


def _new_versioned_bucket(ctx, client, region: str, prefix: str) -> str:
    """Create a uniquely-named, tagged, versioning-enabled bucket in `region`, teardown registered.

    Versioning is confirmed by reading it back: replication requires it on BOTH ends, so an
    unversioned bucket would make every later assertion about the wrong thing.
    """
    name = ctx.unique_name(prefix)
    params = {"Bucket": name}
    if region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": region}
    client.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(client, name))
    client.put_bucket_tagging(
        Bucket=name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real:check", "Value": CHECK},
            ]
        },
    )
    _poll_until(
        lambda: _try(
            lambda: client.put_bucket_versioning(
                Bucket=name, VersioningConfiguration={"Status": "Enabled"}
            )
        ),
        lambda code: code == _SUCCEEDED,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"PutBucketVersioning to be accepted on the new bucket {name} in {region}",
    )
    status = client.get_bucket_versioning(Bucket=name).get("Status")
    assert status == "Enabled", (
        f"bucket {name} in {region} reports versioning {status!r} after PutBucketVersioning; "
        f"replication requires 'Enabled' on both ends"
    )
    return name


def _replication_role(ctx, partition: str, source: str, dest: str, dest_actions: list) -> str:
    """Create (in-check, tagged) the IAM role S3's replication engine assumes; return its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-crr-role-")
    policy_name = "sim2real-behav-crr-policy"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                        "Resource": [f"arn:{partition}:s3:::{source}"],
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObjectVersionForReplication",
                            "s3:GetObjectVersionAcl",
                            "s3:GetObjectVersionTagging",
                        ],
                        "Resource": [f"arn:{partition}:s3:::{source}/*"],
                    },
                    {
                        "Effect": "Allow",
                        "Action": dest_actions,
                        "Resource": [f"arn:{partition}:s3:::{dest}/*"],
                    },
                ],
            }
        ),
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


def _enable_replication(ctx, s3, source: str, config: dict) -> None:
    """PutBucketReplication, then read the rules back.

    The role's trust policy takes a few seconds to become visible to S3's replication engine, so a
    brand-new role can be refused; the bounded retry at first use is what makes that correct (there
    is no API that reports a trust policy has become effective).
    """
    _poll_until(
        lambda: _try(
            lambda: s3.put_bucket_replication(Bucket=source, ReplicationConfiguration=config)
        ),
        lambda code: code == _SUCCEEDED,
        timeout_s=120.0,
        interval_s=5.0,
        description="PutBucketReplication to accept the freshly created replication role",
    )
    stored = s3.get_bucket_replication(Bucket=source)["ReplicationConfiguration"]
    # An empty prefix filter comes back as either {"Prefix": ""} or {}, so the prefix is normalised.
    want = [
        (r["ID"], r["Filter"].get("Prefix") or "", r["DeleteMarkerReplication"]["Status"])
        for r in config["Rules"]
    ]
    got = [
        (
            r["ID"],
            r.get("Filter", {}).get("Prefix") or "",
            r.get("DeleteMarkerReplication", {}).get("Status"),
        )
        for r in stored["Rules"]
    ]
    assert sorted(got) == sorted(want), (
        f"GetBucketReplication on {source} reports rules {got!r}; expected {want!r} — the "
        f"configuration the rest of this check reasons about is not the one in effect"
    )


def _try(fn):
    """The Error.Code of fn(), or _SUCCEEDED when fn() succeeds. Used ONLY inside bounded polls
    whose predicate demands _SUCCEEDED, a value no error code can equal."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "unknown"
    return _SUCCEEDED


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


def _hold_absent(client, bucket, key, prefix, hold_s, *, reason):
    """Assert `key` stays absent from `bucket` for hold_s, on TWO observables: a 404 HeadObject and
    an empty listing of `prefix`. Raises the moment either says otherwise."""
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        try:
            client.head_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            assert status == 404, (
                f"HeadObject on {key!r} in {bucket} failed with HTTP {status!r} rather than 404 "
                f"while proving absence: {reason}"
            )
        else:
            raise AssertionError(f"{key!r} appeared in {bucket}: {reason}")
        found = [
            o["Key"]
            for page in client.get_paginator("list_objects_v2").paginate(
                Bucket=bucket, Prefix=prefix
            )
            for o in page.get("Contents", [])
        ]
        assert found == [], f"{bucket} lists {found!r} under prefix {prefix!r}: {reason}"
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

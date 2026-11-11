"""s3crr-a-version-delete-is-never-replicated-even-with-marker-replication-enabled."""

from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3crr-a-version-delete-is-never-replicated-even-with-marker-replication-enabled"
GROUP = "replication"
SERVICES = ["s3"]

#: What _try returns when its call succeeds; no S3 error code can equal it.
_SUCCEEDED = "<the call succeeded>"
#: GetObject's refusal of a key with no current version, as real S3 returns it.
_NO_SUCH_KEY = ("NoSuchKey", "The specified key does not exist.")
_ARRIVAL_TIMEOUT_S = 240.0
_HOLD_FLOOR_S = 25.0
_HOLD_CAP_S = 60.0


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
    """With DeleteMarkerReplication Enabled, a marker replicates but a delete by VersionId does not.

    The replica of the permanently deleted source version stays readable and gains no marker.
    """
    s3 = ctx.client("s3")
    peer = _peer_region(ctx)
    peer_s3 = ctx.client("s3", region=peer)
    partition = _partition(ctx)

    source = _new_versioned_bucket(ctx, s3, ctx.region, "sim2real-behav-crr-src-")
    dest = _new_versioned_bucket(ctx, peer_s3, peer, "sim2real-behav-crr-dst-")
    role_arn = _replication_role(ctx, partition, source, dest)
    _enable_replication(
        ctx,
        s3,
        source,
        {
            "Role": role_arn,
            "Rules": [
                {
                    "ID": "crr-with-marker-replication",
                    "Status": "Enabled",
                    "Priority": 1,
                    "Filter": {"Prefix": ""},
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Destination": {"Bucket": f"arn:{partition}:s3:::{dest}"},
                }
            ],
        },
    )

    version_key = "crr/version-deleted.bin"
    marker_key = "crr/marker-deleted.bin"
    version_body = (ctx.unique_name("versioned-").encode() + b"-" + bytes(range(256))) * 32
    marker_body = (ctx.unique_name("markered-").encode() + b"-" + bytes(range(256))) * 32
    version_put = s3.put_object(Bucket=source, Key=version_key, Body=version_body)
    s3.put_object(Bucket=source, Key=marker_key, Body=marker_body)

    for key in (version_key, marker_key):
        _poll_until(
            lambda k=key: _try(lambda: peer_s3.head_object(Bucket=dest, Key=k)),
            lambda code: code == _SUCCEEDED,
            timeout_s=_ARRIVAL_TIMEOUT_S,
            interval_s=5.0,
            description=f"the object {key!r} to replicate from {source} into {dest} in {peer}",
        )
    replica = peer_s3.get_object(Bucket=dest, Key=version_key)["Body"].read()
    assert hashlib.sha256(replica).hexdigest() == hashlib.sha256(version_body).hexdigest(), (
        f"the replica of {version_key!r} is {len(replica)} bytes and does not match its "
        f"{len(version_body)}-byte source body; the survival claim below is about THIS replica"
    )

    # --- Permanently remove that one version on the source. Not a marker: the version is gone.
    s3.delete_object(Bucket=source, Key=version_key, VersionId=version_put["VersionId"])
    remaining = _versions(s3, source, version_key)
    assert remaining == [], (
        f"the source key {version_key!r} still has versions "
        f"{[v['VersionId'] for v in remaining]!r} after DeleteObject named VersionId "
        f"{version_put['VersionId']!r}; a version delete removes the version outright"
    )
    assert _error(lambda: s3.get_object(Bucket=source, Key=version_key)) == _NO_SUCH_KEY, (
        f"{version_key!r} is still readable in the SOURCE bucket after its only version was deleted"
    )

    # --- Control on the same rule: a plain delete makes a marker, and THAT replicates.
    marker = s3.delete_object(Bucket=source, Key=marker_key)
    assert marker.get("DeleteMarker") is True, (
        f"deleting {marker_key!r} without a VersionId returned DeleteMarker "
        f"{marker.get('DeleteMarker')!r}; expected True"
    )
    started = time.monotonic()
    _poll_until(
        lambda: _delete_markers(peer_s3, dest, marker_key),
        lambda markers: len(markers) >= 1,
        timeout_s=_ARRIVAL_TIMEOUT_S,
        interval_s=5.0,
        description=(
            f"the delete marker for {marker_key!r} to replicate into {dest} in {peer} under a rule "
            f"whose DeleteMarkerReplication is Enabled"
        ),
    )
    marker_latency_s = time.monotonic() - started
    # The absence window is sized from the measured marker latency, clamped, not a fixed sleep.
    hold_s = min(max(2.0 * marker_latency_s, _HOLD_FLOOR_S), _HOLD_CAP_S)
    assert _error(lambda: peer_s3.get_object(Bucket=dest, Key=marker_key)) == _NO_SUCH_KEY, (
        f"{marker_key!r} is still readable in {dest} although its delete marker replicated there"
    )

    # --- The version-deleted object's replica stays exactly as it was, for a window this run
    # measured on the same wiring.
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        held = peer_s3.get_object(Bucket=dest, Key=version_key)["Body"].read()
        assert hashlib.sha256(held).hexdigest() == hashlib.sha256(version_body).hexdigest(), (
            f"the replica of {version_key!r} in {dest} ({peer}) is now {len(held)} bytes; a version "
            f"delete on the source is never replicated, so the replica must be untouched"
        )
        markers = _delete_markers(peer_s3, dest, version_key)
        assert markers == [], (
            f"{dest} grew {len(markers)} delete marker(s) for {version_key!r}, whose source version "
            f"was deleted by VersionId; only MARKER deletes replicate, and the other key's marker "
            f"arrived in {marker_latency_s:.1f}s on this same wiring"
        )
        surviving = _versions(peer_s3, dest, version_key)
        assert len(surviving) == 1, (
            f"the replica of {version_key!r} in {dest} now has {len(surviving)} version(s) "
            f"({[v['VersionId'] for v in surviving]!r}); expected the single replicated version to "
            f"survive its source version's deletion"
        )
        time.sleep(5.0)


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


def _replication_role(ctx, partition: str, source: str, dest: str) -> str:
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
                        "Action": [
                            "s3:ReplicateObject",
                            "s3:ReplicateDelete",
                            "s3:ReplicateTags",
                        ],
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
    # An empty prefix filter comes back as either {"Prefix": ""} or {}, so the prefix is normalised;
    # the delete-marker switch this check turns on is compared exactly.
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


def _versions(client, bucket: str, key: str) -> list[dict]:
    """Every non-marker version of exactly `key`, paginated."""
    return [
        v
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key)
        for v in page.get("Versions", [])
        if v["Key"] == key
    ]


def _delete_markers(client, bucket: str, key: str) -> list[dict]:
    """Every delete marker on exactly `key`, paginated."""
    return [
        m
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key)
        for m in page.get("DeleteMarkers", [])
        if m["Key"] == key
    ]


def _try(fn):
    """The Error.Code of fn(), or _SUCCEEDED when fn() succeeds. Used ONLY inside bounded polls
    whose predicate demands _SUCCEEDED, a value no error code can equal."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "unknown"
    return _SUCCEEDED


def _error(fn) -> tuple[str, str | None]:
    """The botocore (Error.Code, Error.Message) of fn(); RAISES if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "unknown", err.get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

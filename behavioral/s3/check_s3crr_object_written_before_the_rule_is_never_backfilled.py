"""s3crr-object-written-before-the-rule-is-never-backfilled."""

from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3crr-object-written-before-the-rule-is-never-backfilled"
GROUP = "replication"
SERVICES = ["s3"]

#: What _try returns when its call succeeds; no S3 error code can equal it.
_SUCCEEDED = "<the call succeeded>"
_ARRIVAL_TIMEOUT_S = 240.0
_HOLD_FLOOR_S = 30.0
_HOLD_CAP_S = 75.0


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
    """An object written before the replication rule is never copied; objects written after it are.

    S3 does not backfill existing objects (that takes S3 Batch Replication), and the pre-rule object
    carries no ReplicationStatus.
    """
    s3 = ctx.client("s3")
    peer = _peer_region(ctx)
    peer_s3 = ctx.client("s3", region=peer)
    partition = _partition(ctx)

    source = _new_versioned_bucket(ctx, s3, ctx.region, "sim2real-behav-crr-src-")
    dest = _new_versioned_bucket(ctx, peer_s3, peer, "sim2real-behav-crr-dst-")

    # --- Written BEFORE any replication rule exists. Same bucket, same request shape as the
    # control objects below; the write order is the one thing that differs.
    legacy_key = "crr/legacy.bin"
    legacy_body = (ctx.unique_name("legacy-").encode() + b"-" + bytes(range(256))) * 48
    s3.put_object(Bucket=source, Key=legacy_key, Body=legacy_body)

    role_arn = _replication_role(ctx, partition, source, dest)
    _enable_replication(
        ctx,
        s3,
        source,
        {
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
        },
    )

    # --- Control: an object written AFTER the rule crosses the boundary, and its latency sizes the
    # absence window below.
    first_key = "crr/fresh-first.bin"
    first_body = (ctx.unique_name("fresh-").encode() + b"-" + bytes(range(256))) * 48
    s3.put_object(Bucket=source, Key=first_key, Body=first_body)
    started = time.monotonic()
    _poll_until(
        lambda: _try(lambda: peer_s3.head_object(Bucket=dest, Key=first_key)),
        lambda code: code == _SUCCEEDED,
        timeout_s=_ARRIVAL_TIMEOUT_S,
        interval_s=5.0,
        description=(
            f"the control object {first_key!r}, written after the rule, to reach {dest} in {peer}"
        ),
    )
    latency_s = time.monotonic() - started
    # The absence window is sized from the measured delivery latency, clamped, not a fixed sleep.
    hold_s = min(max(2.0 * latency_s, _HOLD_FLOOR_S), _HOLD_CAP_S)
    arrived = peer_s3.get_object(Bucket=dest, Key=first_key)["Body"].read()
    assert hashlib.sha256(arrived).hexdigest() == hashlib.sha256(first_body).hexdigest(), (
        f"the control replica of {first_key!r} is {len(arrived)} bytes and does not match the "
        f"{len(first_body)}-byte source body, so the pipeline this check measures against is not "
        f"copying bytes faithfully"
    )

    # --- The pre-rule object is unchanged and carries no replication status on the source side.
    legacy_source = s3.get_object(Bucket=source, Key=legacy_key)
    legacy_read = legacy_source["Body"].read()
    assert hashlib.sha256(legacy_read).hexdigest() == hashlib.sha256(legacy_body).hexdigest(), (
        f"the pre-rule object {legacy_key!r} in the SOURCE bucket is {len(legacy_read)} bytes and no "
        f"longer matches what was written ({len(legacy_body)} bytes); this check is about it not "
        f"being COPIED, not about it being altered"
    )
    assert "ReplicationStatus" not in legacy_source, (
        f"the pre-rule object {legacy_key!r} reports ReplicationStatus "
        f"{legacy_source.get('ReplicationStatus')!r} on the source; S3 returns that header only for "
        f"objects that were eligible for replication when they were written, and this one predates "
        f"the rule entirely"
    )

    # --- Absence: it never appears in the peer region, held for a window derived from the control's
    # own measured latency and read on two observables.
    _hold_absent(
        peer_s3,
        dest,
        legacy_key,
        "crr/legacy",
        hold_s,
        reason=(
            f"{legacy_key!r} was written to {source} BEFORE PutBucketReplication, so it is not "
            f"replication material; the control object written after the rule reached {dest} in "
            f"{latency_s:.1f}s on this same wiring"
        ),
    )

    # --- Re-prove delivery: the absence above was not a pipeline that stopped.
    second_key = "crr/fresh-second.bin"
    second_body = (ctx.unique_name("fresh2-").encode() + b"-" + bytes(range(256))) * 48
    s3.put_object(Bucket=source, Key=second_key, Body=second_body)
    _poll_until(
        lambda: _try(lambda: peer_s3.head_object(Bucket=dest, Key=second_key)),
        lambda code: code == _SUCCEEDED,
        timeout_s=_ARRIVAL_TIMEOUT_S,
        interval_s=5.0,
        description=(
            f"a second post-rule object {second_key!r} to replicate, proving the pipeline stayed "
            f"live throughout the {hold_s:.0f}s absence window"
        ),
    )
    replayed = peer_s3.get_object(Bucket=dest, Key=second_key)["Body"].read()
    assert hashlib.sha256(replayed).hexdigest() == hashlib.sha256(second_body).hexdigest(), (
        f"the replica of {second_key!r} is {len(replayed)} bytes and does not match its "
        f"{len(second_body)}-byte source body"
    )


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
    want = [(r["ID"], r["Destination"]["Bucket"]) for r in config["Rules"]]
    got = [(r["ID"], r["Destination"]["Bucket"]) for r in stored["Rules"]]
    assert got == want, (
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

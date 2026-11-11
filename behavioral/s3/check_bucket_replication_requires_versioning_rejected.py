"""bucket-replication-requires-versioning-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-replication-requires-versioning-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketReplication on an unversioned source is rejected with InvalidRequest and its exact
    message and stores no configuration; after versioning is enabled the identical call succeeds and Get
    returns its Role and destination."""
    s3 = ctx.client("s3")
    src = ctx.unique_name("sim2real-behav-replneg-src-")
    dst = ctx.unique_name("sim2real-behav-replneg-dst-")
    _create_bucket(ctx, s3, src)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src))
    _create_bucket(ctx, s3, dst)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, dst))

    # Destination has versioning, but the SOURCE deliberately does not.
    s3.put_bucket_versioning(Bucket=dst, VersioningConfiguration={"Status": "Enabled"})

    role_arn = _create_replication_role(ctx, src, dst)

    rule = {
        "ID": "rule1",
        "Status": "Enabled",
        "Priority": 1,
        "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": f"arn:aws:s3:::{dst}"},
    }

    def _put_replication():
        s3.put_bucket_replication(
            Bucket=src, ReplicationConfiguration={"Role": role_arn, "Rules": [rule]}
        )

    # A freshly-created IAM role can transiently answer AccessDenied/MalformedPolicy
    # before S3 can assume it -- retry on those specifically, but InvalidRequest (the
    # code this check exists to prove) is accepted immediately, not waited past.
    code, message = _retry_while_role_propagates(lambda: _error(_put_replication))
    assert code == "InvalidRequest", code
    assert message == "Versioning must be 'Enabled' on the bucket to apply a replication configuration", message

    # Confirm no replication configuration was actually persisted.
    code2, message2 = _error(lambda: s3.get_bucket_replication(Bucket=src))
    assert code2 == "ReplicationConfigurationNotFoundError", code2
    assert message2 == "The replication configuration was not found", message2

    # Restore: enable versioning on the source, then retry the IDENTICAL call.
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})

    _retry_until_accepted(_put_replication)

    # Independent terminal read at the destination of the mutation (get, not put):
    # the configuration now exists and matches what was requested.
    fetched = s3.get_bucket_replication(Bucket=src)["ReplicationConfiguration"]
    assert fetched["Role"] == role_arn, f"expected Role {role_arn}, got {fetched['Role']}"
    assert fetched["Rules"][0]["Destination"]["Bucket"] == f"arn:aws:s3:::{dst}", (
        f"expected destination arn:aws:s3:::{dst}, got {fetched['Rules'][0]['Destination']['Bucket']}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_ROLE_PROPAGATION_CODES = ("AccessDenied", "MalformedPolicy")


def _retry_while_role_propagates(probe, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Call probe() (returns an (code, message) error pair) until it stops answering with a
    freshly-created-role propagation symptom, or the deadline passes. Never retries
    past InvalidRequest -- that is the code under test, not a propagation symptom."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = probe()
        if code in _ROLE_PROPAGATION_CODES and time.monotonic() < deadline:
            time.sleep(interval_s)
            continue
        return code, message


def _retry_until_accepted(fn, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    """Call fn() until it succeeds, retrying only on a role-propagation symptom within the
    deadline; any other ClientError (or one past the deadline) propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _ROLE_PROPAGATION_CODES and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if to_delete:
                kwargs = {"Bucket": name, "Delete": {"Objects": to_delete}}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                failed = s3.delete_objects(**kwargs).get("Errors")
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


def _create_replication_role(ctx, src: str, dst: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-replneg-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

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
    policy_name = "replication-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, policy_name))

    return role_arn


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

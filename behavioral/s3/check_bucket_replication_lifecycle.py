"""bucket-replication-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "bucket-replication-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketReplication persists a replication rule set, GetBucketReplication returns it
    verbatim, and DeleteBucketReplication removes it so a subsequent Get reverts to the
    ReplicationConfigurationNotFoundError state."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    src = ctx.unique_name("sim2real-behav-repl-src-")
    dst = ctx.unique_name("sim2real-behav-repl-dst-")
    _create_bucket(ctx, src)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=src))
    _create_bucket(ctx, dst)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=dst))
    s3.put_bucket_tagging(Bucket=src, Tagging={"TagSet": _tags_kv()})
    s3.put_bucket_tagging(Bucket=dst, Tagging={"TagSet": _tags_kv()})
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=dst, VersioningConfiguration={"Status": "Enabled"})

    role_name = ctx.unique_name("sim2real-behav-repl-role-")
    trust_policy = {
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_tags_kv(),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetReplicationConfiguration",
                    "s3:ListBucket",
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging",
                ],
                "Resource": [f"arn:aws:s3:::{src}", f"arn:aws:s3:::{src}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                "Resource": f"arn:aws:s3:::{dst}/*",
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-behav-repl-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perm_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    rule_id = ctx.unique_name("rule-")
    replication_config = {
        "Role": role_arn,
        "Rules": [
            {
                "ID": rule_id,
                "Status": "Enabled",
                "Priority": 1,
                "Filter": {"Prefix": ""},
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Destination": {"Bucket": f"arn:aws:s3:::{dst}"},
            }
        ],
    }

    # IAM role propagation can lag a few seconds behind creation.
    def _put_replication():
        s3.put_bucket_replication(Bucket=src, ReplicationConfiguration=replication_config)

    _retry_on_access_denied(_put_replication, timeout_s=60.0)

    got = s3.get_bucket_replication(Bucket=src)
    cfg = got["ReplicationConfiguration"]
    assert cfg["Role"] == role_arn, f"expected Role {role_arn!r}, got {cfg['Role']!r}"
    assert len(cfg["Rules"]) == 1, f"expected exactly 1 rule, got {len(cfg['Rules'])}: {cfg['Rules']!r}"
    assert cfg["Rules"][0]["ID"] == rule_id, f"expected rule ID {rule_id!r}, got {cfg['Rules'][0]['ID']!r}"
    assert cfg["Rules"][0]["Status"] == "Enabled", (
        f"expected rule Status 'Enabled', got {cfg['Rules'][0]['Status']!r}"
    )
    assert cfg["Rules"][0]["Destination"]["Bucket"] == f"arn:aws:s3:::{dst}", (
        f"expected destination arn:aws:s3:::{dst}, got {cfg['Rules'][0]['Destination']['Bucket']!r}"
    )

    s3.delete_bucket_replication(Bucket=src)

    code, message = _error(lambda: s3.get_bucket_replication(Bucket=src))
    assert code == "ReplicationConfigurationNotFoundError", (
        f"expected ReplicationConfigurationNotFoundError after delete, got {code!r}"
    )
    assert message == "The replication configuration was not found", message


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": "bucket-replication-lifecycle"}


def _tags_kv() -> list[dict]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _create_bucket(ctx, name: str, **extra) -> None:
    s3 = ctx.client("s3")
    params: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(extra)
    s3.create_bucket(**params)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_on_access_denied(fn, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "MalformedPolicy", "InvalidRequest") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

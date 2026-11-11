"""update-configured-table-association-analysis-rule-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configured-table-association-analysis-rule-round-trip"
GROUP = "state"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfiguredTableAssociationAnalysisRule changes a LIST rule's allowedResultReceivers from the
    caller's account to the caller plus a second account, and a fresh Get returns the new set with an
    updateTime no earlier than before."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    cr = ctx.client("cleanrooms")
    s3 = ctx.client("s3")

    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-cr-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    db_name, table_name = _create_glue_table(ctx, glue, bucket)
    role_arn = _create_trusted_role(ctx, iam, account_id, db_name, table_name, bucket)

    configured_table = cr.create_configured_table(
        name=ctx.unique_name("sim2real-cr-table-"),
        tableReference={"glue": {"tableName": table_name, "databaseName": db_name}},
        allowedColumns=["id", "value"],
        analysisMethod="DIRECT_QUERY",
    )["configuredTable"]
    table_id = configured_table["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))

    cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"joinColumns": ["id"], "listColumns": ["value"]}}},
    )

    other_account_id = "111122223333"
    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[{
            "accountId": other_account_id,
            "memberAbilities": ["CAN_RECEIVE_RESULTS"],
            "displayName": "invitee",
        }],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
    )["collaboration"]["id"]
    memberships: list[str] = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, memberships))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    )["membership"]["id"]
    memberships.append(membership_id)

    association = _create_association_with_retry(
        cr,
        name="update_rule_assoc",
        membershipIdentifier=membership_id,
        configuredTableIdentifier=table_id,
        roleArn=role_arn,
    )
    assoc_id = association["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table_association(
        configuredTableAssociationIdentifier=assoc_id, membershipIdentifier=membership_id))

    cr.create_configured_table_association_analysis_rule(
        membershipIdentifier=membership_id,
        configuredTableAssociationIdentifier=assoc_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"allowedResultReceivers": [account_id]}}},
    )

    before = cr.get_configured_table_association_analysis_rule(
        membershipIdentifier=membership_id,
        configuredTableAssociationIdentifier=assoc_id,
        analysisRuleType="LIST",
    )["analysisRule"]
    before_receivers = before["policy"]["v1"]["list"]["allowedResultReceivers"]
    assert before_receivers == [account_id], (
        f"expected receivers [{account_id}] as created, got {before_receivers}"
    )

    cr.update_configured_table_association_analysis_rule(
        membershipIdentifier=membership_id,
        configuredTableAssociationIdentifier=assoc_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"allowedResultReceivers": [account_id, other_account_id]}}},
    )

    after = cr.get_configured_table_association_analysis_rule(
        membershipIdentifier=membership_id,
        configuredTableAssociationIdentifier=assoc_id,
        analysisRuleType="LIST",
    )["analysisRule"]
    after_receivers = after["policy"]["v1"]["list"]["allowedResultReceivers"]
    assert sorted(after_receivers) == sorted([account_id, other_account_id]), (
        f"expected receivers [{account_id}, {other_account_id}] after update, got {after_receivers}"
    )
    assert after["updateTime"] >= before["updateTime"], (
        f"expected updateTime to advance, before={before['updateTime']!r} after={after['updateTime']!r}"
    )


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


def _create_glue_table(ctx, glue, bucket):
    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "cr_table"
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": f"s3://{bucket}/{db_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return db_name, table_name


def _create_trusted_role(ctx, iam, account_id, db_name, table_name, bucket):
    role_name = ctx.unique_name("sim2real-cr-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cleanrooms.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateConfiguredTableAssociation assumes the role and validates it can read the
    # Glue table's schema and underlying S3 location synchronously -- a trust-only
    # role, or one whose Glue table points at a bucket that doesn't exist, gets
    # rejected on every attempt.
    policy_name = "sim2real-cr-glue-read"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"],
                "Resource": [
                    f"arn:aws:glue:{ctx.region}:{account_id}:catalog",
                    f"arn:aws:glue:{ctx.region}:{account_id}:database/{db_name}",
                    f"arn:aws:glue:{ctx.region}:{account_id}:table/{db_name}/{table_name}",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return arn


def _create_association_with_retry(cr, timeout_s: float = 180.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cr.create_configured_table_association(**kwargs)["configuredTableAssociation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"association never created, likely IAM propagation delay: {last_exc}")


def _delete_collaboration_then_memberships(cr, collab_id, membership_ids):
    """The creator's ACTIVE membership cannot be deleted, so the collaboration goes first and
    each membership is deleted once it reads COLLABORATION_DELETED."""
    cr.delete_collaboration(collaborationIdentifier=collab_id)
    for membership_id in membership_ids:
        deadline = time.monotonic() + 60
        status = None
        while time.monotonic() < deadline:
            status = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
            if status == "COLLABORATION_DELETED":
                break
            time.sleep(2)
        else:
            raise AssertionError(f"membership {membership_id} never reached COLLABORATION_DELETED: {status}")
        cr.delete_membership(membershipIdentifier=membership_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

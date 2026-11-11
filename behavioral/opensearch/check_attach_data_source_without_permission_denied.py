"""attach-data-source-without-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "attach-data-source-without-permission-denied"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachDataSource by a caller without es:AttachDataSource fails with AccessDeniedException and its
    exact message and creates no attachment; the same call by a permitted caller creates one.
    """
    opensearch = ctx.client("opensearch")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    # AttachDataSource requires the dataSourceArn to reference an actual OpenSearch
    # domain (per the API contract: "The data source must be an Amazon OpenSearch
    # Service domain") -- an ARN from an unrelated service fails ARN-shape validation
    # before authorization is even considered, so we must supply a real domain ARN.
    domain_name = ctx.unique_name("sim2real-ds")[:28].rstrip("-")
    data_source_arn = opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: _delete_domain_ignore_missing(opensearch, domain_name))

    app_name = ctx.unique_name("sim2real-app-")[:30].rstrip("-")
    app_id = opensearch.create_application(name=app_name)["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, app_id))

    role_name = ctx.unique_name("sim2real-behav-osnoperm-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    creds = _assume_role_with_retry(sts, role_arn, "sim2real-osnoperm-session")
    restricted = ctx.client(
        "opensearch",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    code, message = _error(
        lambda: restricted.attach_data_source(id=app_id, dataSourceArn=data_source_arn)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-osnoperm-session "
        f"is not authorized to perform: es:AttachDataSource on resource: "
        f"arn:aws:es:{ctx.region}:{account_id}:domain/* because no identity-based policy "
        "allows the es:AttachDataSource action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the unauthorized attempt did not create an attachment.
    attachments = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    assert attachments == [], f"unauthorized AttachDataSource left an attachment: {attachments!r}"

    # Positive control: the same call, with real permissions, succeeds.
    resp = opensearch.attach_data_source(id=app_id, dataSourceArn=data_source_arn)
    assert resp.get("attachmentId"), f"expected attach to succeed, got {resp!r}"
    attachments_after = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    assert len(attachments_after) == 1, (
        f"expected exactly 1 attachment after the permissioned call, got {attachments_after!r}"
    )
    assert attachments_after[0]["dataSourceArn"] == data_source_arn, (
        f"expected attached dataSourceArn {data_source_arn!r}, "
        f"got {attachments_after[0]['dataSourceArn']!r}"
    )


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _delete_application(ctx, app_id):
    opensearch = ctx.client("opensearch")
    try:
        for attachment in opensearch.list_data_source_attachments(id=app_id).get(
            "attachments", []
        ):
            try:
                opensearch.detach_data_source(
                    id=app_id, dataSourceArn=attachment["dataSourceArn"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        opensearch.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_domain_ignore_missing(opensearch, domain_name):
    from botocore.exceptions import ClientError

    try:
        opensearch.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)[
                "Credentials"
            ]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

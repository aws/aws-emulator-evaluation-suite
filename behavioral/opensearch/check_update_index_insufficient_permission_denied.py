"""update-index-insufficient-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-index-insufficient-permission-denied"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIndex by a role granted only es:DescribeDomain/es:GetIndex fails AccessDeniedException
    and leaves the schema unchanged, while the permitted caller's identical update succeeds."""
    osc = ctx.client("opensearch")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    domain_name = ctx.unique_name("sim2real-uix-")[:28].rstrip("-")
    domain = osc.create_domain(
        DomainName=domain_name,
        # CreateIndex rejects engine versions older than 2.19 with ValidationException
        # (automatic semantic enrichment eligibility is always evaluated).
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    domain_arn = domain["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))

    _wait_domain_active(ctx, osc, domain_name)

    index_name = ctx.unique_name("sim2real-idx-").lower().replace("_", "-")[:60]
    ctx.on_cleanup(lambda: _safe(lambda: osc.delete_index(DomainName=domain_name, IndexName=index_name)))
    osc.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"title": {"type": "text"}}}},
    )

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-uix-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    limited_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["es:DescribeDomain", "es:GetIndex"],
                "Resource": [domain_arn, f"{domain_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="limited", PolicyDocument=json.dumps(limited_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="limited"))

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = None
    for _ in range(10):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-uix")["Credentials"]
            break
        except ClientError:
            time.sleep(3)
    if creds is None:
        raise AssertionError("could not assume the restricted role in time")

    denied_client = ctx.client(
        "opensearch",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    new_schema = {"mappings": {"properties": {"summary": {"type": "text"}}}}

    code, message = _error_detail(
        lambda: denied_client.update_index(
            DomainName=domain_name, IndexName=index_name, IndexSchema=new_schema
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-uix is not authorized "
        f"to perform: es:UpdateIndex on resource: {domain_arn} because no identity-based policy "
        "allows the es:UpdateIndex action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the denied call must not have added the new "summary" field.
    unchanged = osc.get_index(DomainName=domain_name, IndexName=index_name)
    assert "summary" not in _mapping_props(unchanged["IndexSchema"], index_name), (
        f"mappings changed despite denied call: {unchanged['IndexSchema']!r}"
    )

    # Positive control: the same update by the permitted default client succeeds.
    result = osc.update_index(DomainName=domain_name, IndexName=index_name, IndexSchema=new_schema)
    assert result["Status"] == "UPDATED", f"expected Status UPDATED for the permitted call, got {result['Status']!r}"
    updated = osc.get_index(DomainName=domain_name, IndexName=index_name)
    assert "summary" in _mapping_props(updated["IndexSchema"], index_name), (
        f"positive-control update did not persist: {updated['IndexSchema']!r}"
    )

def _mapping_props(index_schema, index_name):
    # GetIndex may wrap mappings under a top-level key named after the index.
    body = index_schema.get(index_name, index_schema)
    return body.get("mappings", {}).get("properties", {})


def _error_detail(fn):
    """(code, message) of the rejection; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, osc, domain_name, timeout_s=1800.0, interval_s=30.0):
    # AWS documents domain creation as typically taking 15-30 minutes.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if not status.get("Processing", True) and status.get("Created", False):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not become active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

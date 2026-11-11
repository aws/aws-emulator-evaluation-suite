"""type-registry-full-lifecycle."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "type-registry-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A private MODULE registers, lists, versions, switches default version and deregisters; a public
    third-party RESOURCE type activates under an alias, and DeactivateType marks it DEPRECATED and unlists it.

    Reference: https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/registry.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfn-").replace("_", "-")
    # us-east-1 is the one region where S3's CreateBucket forbids a
    # LocationConstraint; every other region requires one naming itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # The registry fetches the package as resources.cloudformation.amazonaws.com (not the stack
    # principal), and needs s3:GetBucketLocation on the bucket as well as s3:GetObject.
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCloudFormationRegisterTypeRead",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "resources.cloudformation.amazonaws.com"
                        },
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {
                        "Sid": "AllowCloudFormationRegisterTypeBucketLocation",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "resources.cloudformation.amazonaws.com"
                        },
                        "Action": "s3:GetBucketLocation",
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                ],
            }
        ),
    )

    suffix = uuid.uuid4().hex[:10]
    type_name = f"Sim2RealBehav{suffix}::Cfn{suffix}::Test::MODULE"

    key1 = "module-v1.zip"
    # A new bucket policy can take a moment to apply, so registration is retried on FAILED.
    token1, reg1 = _register_module_with_retry(
        cfn, s3, bucket, key1, type_name, description="v1"
    )
    type_arn = reg1["TypeArn"]
    version_arn_1 = reg1["TypeVersionArn"]
    ctx.on_cleanup(lambda: _safe_deregister(cfn, type_arn))

    # RegistrationStatusFilter defaults to IN_PROGRESS, so a registration that has already
    # reached COMPLETE is invisible unless COMPLETE is asked for explicitly.
    registrations = cfn.list_type_registrations(
        TypeName=type_name, Type="MODULE", RegistrationStatusFilter="COMPLETE"
    )
    assert token1 in registrations["RegistrationTokenList"], (
        f"ListTypeRegistrations(COMPLETE) missing our token {token1!r}: "
        f"{registrations['RegistrationTokenList']}"
    )

    versions = cfn.list_type_versions(Arn=type_arn)
    version_ids_1 = {v["VersionId"] for v in versions["TypeVersionSummaries"]}
    assert len(version_ids_1) == 1, f"expected exactly 1 version, got {version_ids_1}"

    key2 = "module-v2.zip"
    _token2, reg2 = _register_module_with_retry(
        cfn, s3, bucket, key2, type_name, description="v2"
    )
    version_arn_2 = reg2["TypeVersionArn"]

    versions_after = cfn.list_type_versions(Arn=type_arn)
    version_ids_2 = {v["VersionId"] for v in versions_after["TypeVersionSummaries"]}
    assert len(version_ids_2) == 2, (
        f"expected 2 versions after second registration, got {version_ids_2}"
    )

    described_before = cfn.describe_type(Arn=type_arn)
    assert described_before["DefaultVersionId"] not in (None, ""), (
        "no default version set"
    )
    default_before = described_before["DefaultVersionId"]

    cfn.set_type_default_version(Arn=version_arn_2)
    described_after = cfn.describe_type(Arn=type_arn)
    assert described_after["DefaultVersionId"] != default_before, (
        "default version did not change"
    )
    assert version_arn_2.endswith(described_after["DefaultVersionId"]), (
        f"default version {described_after['DefaultVersionId']} does not match set version arn {version_arn_2}"
    )

    listed_types = cfn.list_types(
        Visibility="PRIVATE", Filters={"Category": "REGISTERED"}
    )
    assert any(t["TypeArn"] == type_arn for t in listed_types["TypeSummaries"]), (
        "ListTypes(PRIVATE/REGISTERED) does not contain our registered module"
    )

    cfn.deregister_type(Arn=version_arn_1)
    versions_final = cfn.list_type_versions(Arn=type_arn)
    remaining_ids = {v["VersionId"] for v in versions_final["TypeVersionSummaries"]}
    assert version_arn_1.split("/")[-1] not in remaining_ids, (
        "deregistered version still listed"
    )

    # An AWS-owned extension activated by PublicTypeArn without a role is AccessDenied, so a
    # third-party RESOURCE type is activated by TypeName+PublisherId with an execution role.
    candidate = _pick_public_third_party_resource_type(cfn)
    assert candidate is not None, (
        "no public third-party RESOURCE extensions discoverable via ListTypes"
    )

    # ActivateType requires an ExecutionRoleArn for a RESOURCE type; activation invokes no handler,
    # so a trust-only role suffices.
    exec_role_arn = _create_extension_exec_role(ctx)
    # A per-run TypeNameAlias gives this run its own private copy of the public type.
    alias = f"Sim2Real::Alias{suffix}::Registry"
    activated = _activate_with_retry(cfn, candidate, exec_role_arn, alias)
    activated_arn = activated["Arn"]
    ctx.on_cleanup(lambda: _safe_deactivate(cfn, activated_arn))

    assert _appears_in_activated_list(cfn, activated_arn), (
        "activated extension missing from ListTypes(PRIVATE/ACTIVATED)"
    )
    described_activated = cfn.describe_type(Arn=activated_arn)
    # DescribeType keyed by the PRIVATE activation Arn carries no "IsActivated" field at all
    # (that appears only when describing the PUBLIC extension), so Visibility is the signal.
    assert described_activated["Visibility"] == "PRIVATE", (
        f"expected Visibility='PRIVATE' for the activated copy, got {described_activated['Visibility']!r}"
    )
    assert described_activated["TypeName"] == alias, (
        f"expected the activated copy to be named by its alias {alias!r}, got {described_activated['TypeName']!r}"
    )

    # DeactivateType keeps the private registration: DescribeType still resolves the Arn.
    cfn.deactivate_type(Arn=activated_arn)
    described_deactivated = cfn.describe_type(Arn=activated_arn)
    assert described_deactivated["DeprecatedStatus"] == "DEPRECATED", (
        f"expected DeprecatedStatus='DEPRECATED' after DeactivateType, got "
        f"{described_deactivated['DeprecatedStatus']!r}"
    )
    assert not _appears_in_activated_list(cfn, activated_arn), (
        "deactivated extension still present in ListTypes(PRIVATE/ACTIVATED)"
    )


def _pick_public_third_party_resource_type(cfn):
    token = None
    for _ in range(60):
        kwargs = {
            "Visibility": "PUBLIC",
            "Filters": {"Category": "THIRD_PARTY"},
            "Type": "RESOURCE",
            "MaxResults": 100,
        }
        if token:
            kwargs["NextToken"] = token
        resp = cfn.list_types(**kwargs)
        for summary in resp.get("TypeSummaries", []):
            if summary.get("TypeName") and summary.get("PublisherId"):
                return summary
        token = resp.get("NextToken")
        if not token:
            break
    return None


def _create_extension_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfn-type-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    return role_arn


def _activate_with_retry(cfn, candidate, role_arn: str, alias: str, attempts: int = 6, wait_s: float = 10.0):
    # A just-created role's trust policy is not always visible to ActivateType yet.
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return cfn.activate_type(
                Type="RESOURCE",
                TypeName=candidate["TypeName"],
                PublisherId=candidate["PublisherId"],
                TypeNameAlias=alias,
                ExecutionRoleArn=role_arn,
            )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < attempts:
                time.sleep(wait_s)
    raise AssertionError(
        f"ActivateType never succeeded for {candidate.get('TypeName')!r} after {attempts} "
        f"attempts; last error: {_code(last_exc)}: {last_exc}"
    )


def _appears_in_activated_list(cfn, arn: str, max_pages: int = 20) -> bool:
    token = None
    for _ in range(max_pages):
        kwargs = {"Visibility": "PRIVATE", "Filters": {"Category": "ACTIVATED"}, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = cfn.list_types(**kwargs)
        # TypeSummary carries "TypeArn", never "Arn" -- DescribeType uses "Arn" instead.
        for summary in resp.get("TypeSummaries", []):
            if summary.get("TypeArn") == arn:
                return True
        token = resp.get("NextToken")
        if not token:
            break
    return False


def _code(exc) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _error_code(fn):
    try:
        fn()
        return None
    except Exception as exc:  # noqa: BLE001
        return _code(exc)


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _register_module_with_retry(
    cfn, s3, bucket, key, type_name, description, attempts=8, retry_wait_s=20.0
):
    """RegisterType polled to a terminal state, retried with a fresh upload while the bucket
    policy propagates; only COMPLETE is accepted.
    """
    last_reg = None
    for attempt in range(1, attempts + 1):
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=_module_zip_bytes(type_name=type_name, description=description),
        )
        token = cfn.register_type(
            Type="MODULE",
            TypeName=type_name,
            SchemaHandlerPackage=f"s3://{bucket}/{key}",
        )["RegistrationToken"]
        reg = _poll_until(
            lambda: cfn.describe_type_registration(RegistrationToken=token),
            lambda r: r["ProgressStatus"] != "IN_PROGRESS",
            timeout_s=180.0,
            interval_s=5.0,
        )
        if reg["ProgressStatus"] == "COMPLETE":
            return token, reg
        last_reg = reg
        if attempt < attempts:
            time.sleep(retry_wait_s)
    raise AssertionError(
        f"registration of {key} failed after {attempts} attempts: {last_reg}"
    )


def _module_zip_bytes(type_name: str, description: str) -> bytes:
    # A MODULE package needs fragments/fragment.json and schema.json. The schema validates the
    # fragment's top-level keys, so it declares Resources and allows additional properties.
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"sim2real behavioral test module ({description})",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    schema = {
        "typeName": type_name,
        "description": f"sim2real behavioral test module ({description})",
        "properties": {"Resources": {"type": "object"}},
        "additionalProperties": True,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()


def _safe_deregister(cfn, type_arn: str) -> None:
    try:
        # The default version cannot be deregistered alone; deregistering the type removes it.
        for v in cfn.list_type_versions(Arn=type_arn)["TypeVersionSummaries"]:
            if v.get("IsDefaultVersion"):
                continue
            try:
                cfn.deregister_type(Arn=v["Arn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "TypeNotFoundException":
                    raise
        cfn.deregister_type(Arn=type_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _safe_deactivate(cfn, arn: str) -> None:
    try:
        cfn.deactivate_type(Arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""concurrent-provisioning-template-version-creation-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-provisioning-template-version-creation-conflict"
GROUP = "concurrency"
SERVICES = ["iot"]

# AWS IoT Core hard, non-adjustable quota: "Versions per fleet provisioning template".
_MAX_VERSIONS = 5


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """At the 5-version limit, concurrent CreateProvisioningTemplateVersion calls all
    fail with VersionsLimitExceededException and its exact message, versions stay
    unchanged, and freeing one admits one more."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")
    template_name = ctx.unique_name("sim2real-pt-")[:36]
    role_arn = _create_provisioning_role(ctx, iam)

    body = _template_body()
    create_resp = _poll_create_template(iot, template_name, body, role_arn)
    ctx.on_cleanup(lambda: _delete_template(iot, template_name))
    assert create_resp["defaultVersionId"] == 1, f"expected initial version 1, got {create_resp['defaultVersionId']}"

    # Fill up to the cap (1 initial version + 4 more = 5). Positive control: creating
    # versions while under the cap must succeed.
    for _ in range(1, _MAX_VERSIONS):
        iot.create_provisioning_template_version(
            templateName=template_name, templateBody=body, setAsDefault=False
        )

    versions_before = _list_version_ids(iot, template_name)
    assert len(versions_before) == _MAX_VERSIONS, f"expected {_MAX_VERSIONS} versions after filling to cap, got {versions_before}"

    # At the cap: two concurrent attempts to add a 6th version must both be rejected,
    # and the count must stay at exactly 5 (no double-increment / corruption).
    barrier = threading.Barrier(2)

    def _attempt(_: int):
        barrier.wait()
        try:
            iot.create_provisioning_template_version(
                templateName=template_name, templateBody=body, setAsDefault=False
            )
            return ("ok", None, None)
        except ClientError as e:
            return ("err", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in (pool.submit(_attempt, 0), pool.submit(_attempt, 1))]

    assert all(r[0] == "err" for r in results), f"expected both over-cap creates rejected, got {results}"
    assert all(
        r[1] == "VersionsLimitExceededException" for r in results
    ), f"expected VersionsLimitExceededException for both, got {results}"
    expected = (
        f"Can't create a template version for the template {template_name}, the maximum number "
        "of template versions has been reached"
    )
    for _kind, _code, message in results:
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    versions_after = _list_version_ids(iot, template_name)
    assert versions_after == versions_before, (
        f"version set changed despite both creates being rejected: "
        f"before={versions_before}, after={versions_after}"
    )

    # Restore: freeing one slot below the cap must let an identical call succeed again
    # (the cap is a live count, not a one-shot latch that stays tripped).
    freed_version_id = max(v for v in versions_before if v != create_resp["defaultVersionId"])
    iot.delete_provisioning_template_version(templateName=template_name, versionId=freed_version_id)
    versions_after_delete = _list_version_ids(iot, template_name)
    assert freed_version_id not in versions_after_delete, (
        f"expected version {freed_version_id} gone after delete, still present in {versions_after_delete}"
    )
    assert len(versions_after_delete) == _MAX_VERSIONS - 1, (
        f"expected {_MAX_VERSIONS - 1} versions after freeing one slot, got {versions_after_delete}"
    )

    restore_resp = iot.create_provisioning_template_version(
        templateName=template_name, templateBody=body, setAsDefault=False
    )
    versions_restored = _list_version_ids(iot, template_name)
    assert restore_resp["versionId"] not in versions_before, (
        f"expected a newly minted version id, got {restore_resp['versionId']} which was already in {versions_before}"
    )
    assert len(versions_restored) == _MAX_VERSIONS, (
        f"expected the identical call to succeed once under cap again, got {versions_restored}"
    )


def _template_body() -> str:
    return json.dumps(
        {
            "Parameters": {"AWS::IoT::Certificate::Id": {"Type": "String"}},
            "Resources": {
                "certificate": {
                    "Type": "AWS::IoT::Certificate",
                    "Properties": {
                        "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                        "Status": "ACTIVE",
                    },
                },
                "thing": {
                    "Type": "AWS::IoT::Thing",
                    "Properties": {"ThingName": {"Ref": "AWS::IoT::Certificate::Id"}},
                },
            },
        }
    )


def _create_provisioning_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-provrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return role["Arn"]


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_create_template(iot, template_name: str, body: str, role_arn: str, timeout_s: float = 30.0):
    # A just-created IAM role can lag briefly before AWS IoT's control plane can
    # validate its trust policy; poll on the documented InvalidRequestException
    # rather than sleeping a fixed window.
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return iot.create_provisioning_template(
                templateName=template_name, templateBody=body, provisioningRoleArn=role_arn
            )
        except ClientError as e:
            last_error = e
            if e.response["Error"]["Code"] != "InvalidRequestException":
                raise
            time.sleep(2)
    raise AssertionError(f"CreateProvisioningTemplate never succeeded: {last_error}")


def _list_version_ids(iot, template_name: str):
    return sorted(
        v["versionId"]
        for v in iot.list_provisioning_template_versions(templateName=template_name)["versions"]
    )


def _delete_template(iot, template_name: str) -> None:
    try:
        versions = iot.list_provisioning_template_versions(templateName=template_name)["versions"]
        for v in versions:
            if not v.get("isDefaultVersion"):
                try:
                    iot.delete_provisioning_template_version(
                        templateName=template_name, versionId=v["versionId"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_provisioning_template(templateName=template_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

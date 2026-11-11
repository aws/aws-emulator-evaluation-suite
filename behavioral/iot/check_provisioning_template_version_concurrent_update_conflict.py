"""provisioning-template-version-concurrent-update-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioning-template-version-concurrent-update-conflict"
GROUP = "concurrency"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateProvisioningTemplateVersion(setAsDefault=True) calls either succeed with a
    unique version or fail with ConflictingResourceUpdateException, and the final default is one of
    the successful racers' versions."""
    iot = ctx.client("iot")
    role_arn = _create_provisioning_role(ctx)
    template_name = ctx.unique_name("sim2realptc-")

    create_resp = _retry_on_codes(
        lambda: iot.create_provisioning_template(
            templateName=template_name,
            templateBody=_template_body("racer-base"),
            provisioningRoleArn=role_arn,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        codes=("InvalidRequestException", "UnauthorizedException"),
        timeout_s=45,
    )
    ctx.on_cleanup(lambda: iot.delete_provisioning_template(templateName=template_name))
    assert create_resp["defaultVersionId"] == 1, (
        f"expected initial defaultVersionId 1, got {create_resp['defaultVersionId']}"
    )

    # IoT keeps at most 5 versions per template; base + racers must stay within that cap.
    n_racers = 3

    def _racer(i: int):
        try:
            resp = iot.create_provisioning_template_version(
                templateName=template_name,
                templateBody=_template_body(f"racer-{i}"),
                setAsDefault=True,
            )
            return ("ok", resp["versionId"])
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "ConflictingResourceUpdateException":
                raise AssertionError(
                    f"unexpected error code under contention: {code}"
                ) from exc
            return ("conflict", exc.response["Error"].get("Message"))

    results = []
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_racer, i) for i in range(n_racers)]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [v for (kind, v) in results if kind == "ok"]
    expected = "Unable to create template version due to a conflicting modification"
    for message in (v for (kind, v) in results if kind == "conflict"):
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert len(successes) >= 1, "no racer succeeded under contention"
    assert len(set(successes)) == len(successes), "duplicate versionId handed out to racers"

    all_versions = iot.list_provisioning_template_versions(templateName=template_name)[
        "versions"
    ]
    assert len(all_versions) == 1 + len(successes), (
        f"expected 1 base version + {len(successes)} accepted racer version(s) "
        f"= {1 + len(successes)}, got {len(all_versions)}"
    )

    final = iot.describe_provisioning_template(templateName=template_name)
    assert final["defaultVersionId"] in successes, (
        f"defaultVersionId {final['defaultVersionId']} is not one of the racers "
        f"that actually succeeded: {successes}"
    )
    assert final["defaultVersionId"] != 1, (
        "defaultVersionId is still the pre-race base version 1; "
        "no setAsDefault=True racer took effect"
    )


def _template_body(thing_name_default: str) -> str:
    # FLEET_PROVISIONING (the default type) rejects a body without a Certificate resource
    return json.dumps(
        {
            "Parameters": {
                "ThingName": {"Type": "String", "Default": thing_name_default},
                "AWS::IoT::Certificate::Id": {"Type": "String"},
            },
            "Resources": {
                "thing": {
                    "Type": "AWS::IoT::Thing",
                    "Properties": {"ThingName": {"Ref": "ThingName"}},
                },
                "certificate": {
                    "Type": "AWS::IoT::Certificate",
                    "Properties": {
                        "CertificateId": {"Ref": "AWS::IoT::Certificate::Id"},
                        "Status": "INACTIVE",
                    },
                },
            },
        }
    )


def _create_provisioning_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-ptc-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _retry_on_codes(fn, codes, timeout_s: float = 45.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

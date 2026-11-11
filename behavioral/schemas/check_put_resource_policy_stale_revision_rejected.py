"""put-resource-policy-stale-revision-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-stale-revision-rejected"
GROUP = "overly-permissive"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a stale RevisionId is rejected; the correct-revision path in the same file succeeds."""
    schemas = ctx.client("schemas")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = schemas.meta.region_name

    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    put1 = schemas.put_resource_policy(
        RegistryName=registry, Policy=json.dumps(_policy_doc(account_id, region, registry, "v1"))
    )
    ctx.on_cleanup(lambda: schemas.delete_resource_policy(RegistryName=registry))
    revision1 = put1["RevisionId"]

    # Positive control: updating with the correct (current) revision succeeds.
    put2 = schemas.put_resource_policy(
        RegistryName=registry,
        Policy=json.dumps(_policy_doc(account_id, region, registry, "v2")),
        RevisionId=revision1,
    )
    revision2 = put2["RevisionId"]
    assert revision2 != revision1, f"expected a fresh RevisionId after a successful update, got {revision2!r} again"

    # Negative: reusing the now-stale revision1 to update again is rejected.
    err = _error(
        lambda: schemas.put_resource_policy(
            RegistryName=registry,
            Policy=json.dumps(_policy_doc(account_id, region, registry, "v3")),
            RevisionId=revision1,
        )
    )
    assert err["Code"] == "PreconditionFailedException", f"unexpected error reusing a stale revision: {err!r}"
    assert err["Message"] == (
        "The RevisionId provided does not match the latest RevisionId for the registry policy."
    ), f"unexpected policy_stale message: {err['Message']!r}"

    unaffected = schemas.get_resource_policy(RegistryName=registry)
    assert unaffected["RevisionId"] == revision2, (
        f"stale-revision update must not advance state: expected RevisionId {revision2!r}, got {unaffected['RevisionId']!r}"
    )
    unaffected_sid = json.loads(unaffected["Policy"])["Statement"][0]["Sid"]
    assert unaffected_sid == "v2", f"stale-revision update must not apply: expected Sid 'v2', got {unaffected_sid!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _policy_doc(account_id: str, region: str, registry_name: str, sid: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": [account_id]},
                "Action": ["schemas:DescribeSchema"],
                "Resource": [
                    f"arn:aws:schemas:{region}:{account_id}:registry/{registry_name}",
                    f"arn:aws:schemas:{region}:{account_id}:schema/{registry_name}*",
                ],
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

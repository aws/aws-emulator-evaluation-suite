"""list-identities-creation-date-timestamp-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-identities-creation-date-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIdentities CreationDate/LastModifiedDate match DescribeIdentity's values for the same
    identity at full sub-second precision, with no truncation or rounding on either path."""
    cognito = ctx.client("cognito-identity")

    pool_name = ctx.unique_name("sim2real-idp-")
    created = cognito.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": "true"},
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: cognito.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(
        lambda: cognito.delete_identities(IdentityIdsToDelete=[identity_id])
    )

    described = cognito.describe_identity(IdentityId=identity_id)
    creation_date_direct = described["CreationDate"]
    last_modified_direct = described["LastModifiedDate"]

    listed_entry = _poll_until_identity_listed(ctx, pool_id, identity_id)

    assert listed_entry["CreationDate"] == creation_date_direct, (
        f"ListIdentities CreationDate {listed_entry['CreationDate']!r} != "
        f"DescribeIdentity CreationDate {creation_date_direct!r} for identity {identity_id}"
    )
    assert listed_entry["LastModifiedDate"] == last_modified_direct, (
        f"ListIdentities LastModifiedDate {listed_entry['LastModifiedDate']!r} != "
        f"DescribeIdentity LastModifiedDate {last_modified_direct!r} for identity {identity_id}"
    )
    assert listed_entry["CreationDate"].microsecond == creation_date_direct.microsecond, (
        f"ListIdentities CreationDate microsecond {listed_entry['CreationDate'].microsecond} != "
        f"DescribeIdentity CreationDate microsecond {creation_date_direct.microsecond}"
    )


def _poll_until_identity_listed(ctx, pool_id: str, identity_id: str, timeout_s: float = 30.0):
    cognito = ctx.client("cognito-identity")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cognito.list_identities(IdentityPoolId=pool_id, MaxResults=60)
        for entry in resp.get("Identities", []):
            if entry["IdentityId"] == identity_id:
                return entry
        time.sleep(1.0)
    raise AssertionError(f"identity {identity_id} never appeared in ListIdentities within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

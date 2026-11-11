"""batch-get-profile-mixed-valid-invalid."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-profile-mixed-valid-invalid"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetProfile with one real and one nonexistent ProfileId returns the real one in Profiles and the bogus one in Errors."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    bogus_id = "0" * 32

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    profile_id = cp.create_profile(DomainName=domain, FirstName="Jamie")["ProfileId"]

    resp = cp.batch_get_profile(DomainName=domain, ProfileIds=[profile_id, bogus_id])

    profiles_returned = resp.get("Profiles", [])
    errors_returned = resp.get("Errors", [])
    profile_ids_returned = {p["ProfileId"] for p in profiles_returned}
    error_ids_returned = {e["ProfileId"] for e in errors_returned}
    assert profile_ids_returned == {profile_id}, (
        f"expected Profiles to contain only the real id {profile_id!r}, got {profile_ids_returned!r}"
    )
    assert error_ids_returned == {bogus_id}, (
        f"expected Errors to contain only the bogus id {bogus_id!r}, got {error_ids_returned!r}"
    )
    error_codes = {e["Code"] for e in errors_returned}
    assert error_codes == {"404"}, (
        f"expected the bogus id's error Code to be '404', got {error_codes!r}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

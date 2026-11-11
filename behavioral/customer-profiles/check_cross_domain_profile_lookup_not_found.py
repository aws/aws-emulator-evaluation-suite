"""cross-domain-profile-lookup-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-domain-profile-lookup-not-found"
GROUP = "overly-permissive"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A profile created in domain A is invisible when looked up through domain B (tenant isolation); domain A sees it fine."""
    cp = ctx.client("customer-profiles")
    domain_a = ctx.unique_name("sim2real-cp-doma-")
    domain_b = ctx.unique_name("sim2real-cp-domb-")

    tags_kw = {"Tags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}}
    cp.create_domain(DomainName=domain_a, DefaultExpirationDays=30, **tags_kw)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain_a)))
    cp.create_domain(DomainName=domain_b, DefaultExpirationDays=30, **tags_kw)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain_b)))

    profile_id = cp.create_profile(DomainName=domain_a, FirstName="Isolated")["ProfileId"]

    cross = cp.batch_get_profile(DomainName=domain_b, ProfileIds=[profile_id])
    cross_profile_ids = {p["ProfileId"] for p in cross.get("Profiles", [])}
    assert profile_id not in cross_profile_ids, (
        f"profile {profile_id} created in {domain_a} must not be visible via {domain_b}, "
        f"got Profiles={cross_profile_ids!r}"
    )
    cross_errors = {e["ProfileId"]: e for e in cross.get("Errors", [])}
    assert profile_id in cross_errors, (
        f"expected {profile_id} in BatchGetProfile Errors when queried via foreign domain "
        f"{domain_b}, got Errors={cross_errors!r}"
    )
    cross_err = cross_errors[profile_id]
    assert cross_err.get("Code") == "404", (
        f"expected Code=404 for a cross-domain profile lookup, got {cross_err!r}"
    )

    # positive control: looked up through the domain it actually belongs to, it is found.
    same_domain = cp.batch_get_profile(DomainName=domain_a, ProfileIds=[profile_id])
    same_domain_ids = {p["ProfileId"] for p in same_domain.get("Profiles", [])}
    assert same_domain_ids == {profile_id}, (
        f"expected profile {profile_id} visible via its own domain {domain_a}, got {same_domain_ids!r}"
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

"""create-domain-association-invalid-domain-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-domain-association-invalid-domain-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainAssociation rejects a domainName that fails the DNS-label pattern and creates nothing."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(appId=app_id, branchName=branch_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    bad_domain = "not_a_valid_domain!!"
    err = _client_error(
        lambda: amplify.create_domain_association(
            appId=app_id,
            domainName=bad_domain,
            subDomainSettings=[{"prefix": "", "branchName": branch_name}],
        )
    )
    assert err == (
        "ValidationException",
        f"1 validation error detected: Value '{bad_domain}' at 'domainName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"^(((?!-)[A-Za-z0-9-]{0,62}[A-Za-z0-9])\.)+((?!-)[A-Za-z0-9-]{1,62}[A-Za-z0-9])(\.)?$",
    ), err

    associations = amplify.list_domain_associations(appId=app_id)["domainAssociations"]
    assert associations == [], associations

    # Positive control: a validly patterned domain name is accepted.
    good_domain = f"{ctx.unique_name('sim2real-amplify-dom')}.example.com"
    amplify.create_domain_association(
        appId=app_id,
        domainName=good_domain,
        subDomainSettings=[{"prefix": "", "branchName": branch_name}],
    )
    ctx.on_cleanup(
        lambda: _ignore(lambda: amplify.delete_domain_association(appId=app_id, domainName=good_domain))
    )

    # Independent read at the destination: the association must actually exist, not merely
    # be echoed back by the call that created it.
    associations = amplify.list_domain_associations(appId=app_id)["domainAssociations"]
    domain_names = [a["domainName"] for a in associations]
    assert domain_names == [good_domain], (good_domain, domain_names)


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises, so an emulator
    accepting a call real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded: {result!r}")


def _create_app(ctx) -> str:
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real": CHECK})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

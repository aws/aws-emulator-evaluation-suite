"""domain-association-status-progresses."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-association-status-progresses"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainAssociation kicks off async provisioning: domainStatus moves off its initial value."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(appId=app_id, branchName=branch_name)
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    domain_name = f"{ctx.unique_name('sim2real-amplify-dom')}.example.com"
    created = amplify.create_domain_association(
        appId=app_id,
        domainName=domain_name,
        subDomainSettings=[{"prefix": "", "branchName": branch_name}],
    )["domainAssociation"]
    ctx.on_cleanup(
        lambda: _ignore(lambda: amplify.delete_domain_association(appId=app_id, domainName=domain_name))
    )
    initial_status = created["domainStatus"]

    # Real AWS asynchronously requests an ACM certificate and moves the domain out of its
    # initial state within tens of seconds; we do not own the domain, so it can never reach
    # AVAILABLE, but a bounded poll for a status change from the initial value is legitimate.
    final_status = initial_status
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        got = amplify.get_domain_association(appId=app_id, domainName=domain_name)["domainAssociation"]
        final_status = got["domainStatus"]
        if final_status != initial_status:
            break
        time.sleep(5)

    assert final_status != initial_status, f"domainStatus never left {initial_status!r}"


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_app(ctx) -> str:
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name)["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

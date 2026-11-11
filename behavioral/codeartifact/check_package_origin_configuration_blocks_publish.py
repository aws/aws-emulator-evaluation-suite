"""package-origin-configuration-blocks-publish."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-origin-configuration-blocks-publish"
GROUP = 'package-origin-blocked'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        "the publish SUCCEEDED where the origin configuration blocks it — no error code to compare"
    )


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _versions(ca, domain, repo, **scope):
    out = []
    for page in ca.get_paginator("list_package_versions").paginate(
            domain=domain, repository=repo, **scope):
        out.extend(page["versions"])
    return sorted(v["version"] for v in out)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A package's origin restrictions default to publish ALLOW / upstream BLOCK; publish=BLOCK refuses
    the next publish with ValidationException and its exact message and stores nothing, and restoring
    ALLOW lets 2.0.0 publish as Published."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-origin-switch"
    content = b"origin-switch-payload\n"
    scope = dict(format="generic", namespace="sim2real", package=package)
    publish = dict(assetContent=content, assetName="payload.bin",
                   assetSHA256=hashlib.sha256(content).hexdigest())

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    ca.publish_package_version(domain=domain, repository=repo, packageVersion="1.0.0",
                               **publish, **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))
    default_restrictions = ca.describe_package(
        domain=domain, repository=repo, **scope)["package"]["originConfiguration"]["restrictions"]
    assert default_restrictions == {"publish": "ALLOW", "upstream": "BLOCK"}, (
        f"an internally published generic package defaults to {default_restrictions!r}; expected "
        f"publish ALLOW and upstream BLOCK"
    )

    blocked = ca.put_package_origin_configuration(
        domain=domain, repository=repo,
        restrictions={"publish": "BLOCK", "upstream": "BLOCK"}, **scope)
    assert blocked["originConfiguration"]["restrictions"]["publish"] == "BLOCK", (
        f"the switch echoed {blocked['originConfiguration']['restrictions']!r}, expected "
        f"publish BLOCK"
    )

    code, message = _error(lambda: ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="2.0.0", **publish, **scope))
    assert code == "ValidationException", (
        f"a publish under publish=BLOCK returned {code!r}, expected ValidationException"
    )
    assert message == "This package is configured to block new versions from being published.", (
        f"the refusal said {message!r}, expected it to name the package's own configuration"
    )
    assert _versions(ca, domain, repo, **scope) == ["1.0.0"], (
        f"after the blocked publish the package holds "
        f"{_versions(ca, domain, repo, **scope)!r}, expected only the pre-existing ['1.0.0']"
    )

    ca.put_package_origin_configuration(
        domain=domain, repository=repo,
        restrictions={"publish": "ALLOW", "upstream": "BLOCK"}, **scope)
    landed = ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="2.0.0", **publish, **scope)
    assert landed["status"] == "Published", (
        f"the positive control (identical publish, publish=ALLOW again) reported "
        f"{landed['status']!r}, expected Published"
    )
    assert _versions(ca, domain, repo, **scope) == ["1.0.0", "2.0.0"], (
        f"after the control the package holds {_versions(ca, domain, repo, **scope)!r}, expected "
        f"both versions"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

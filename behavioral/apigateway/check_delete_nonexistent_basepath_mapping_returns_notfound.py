"""delete-nonexistent-basepath-mapping-returns-notfound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-nonexistent-basepath-mapping-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Delete/GetBasePathMapping under a nonexistent domain name return NotFoundException."""
    apigw = ctx.client("apigateway")
    domain = ctx.unique_name("sim2real-nobpm-") + ".example.org"

    existing = {d["domainName"] for d in _list_domain_names(apigw)}
    assert domain not in existing, f"generated domain {domain!r} collided with an existing domain name"

    code, message = _error(
        lambda: apigw.delete_base_path_mapping(domainName=domain, basePath="unmapped")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid domain name identifier specified", f"unexpected message: {message!r}"

    get_code, get_code_message = _error(
        lambda: apigw.get_base_path_mapping(domainName=domain, basePath="unmapped")
    )
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_code_message == "Invalid domain name identifier specified", f"unexpected message: {get_code_message!r}"


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _list_domain_names(apigw):
    items = []
    kwargs = {}
    while True:
        resp = apigw.get_domain_names(**kwargs)
        items.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
        kwargs["position"] = position
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

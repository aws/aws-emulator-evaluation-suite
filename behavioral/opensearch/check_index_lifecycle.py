"""index-lifecycle."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "index-lifecycle"
GROUP = 'index'
SERVICES = ['opensearch']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _pick_latest_opensearch_version(osc) -> str:
    """The newest `OpenSearch_*` engine version this account can provision.

    CreateIndex/UpdateIndex reject engines that are not recent enough, and a pinned version ages out.
    """
    versions: list[str] = []
    resp = osc.list_versions(MaxResults=100)
    versions.extend(resp.get("Versions", []))
    while resp.get("NextToken"):
        resp = osc.list_versions(MaxResults=100, NextToken=resp["NextToken"])
        versions.extend(resp.get("Versions", []))

    def key(v):
        try:
            major, minor = v.split("_", 1)[1].split(".")
            return (int(major), int(minor))
        except Exception:
            return (0, 0)

    os_versions = sorted((v for v in versions if v.startswith("OpenSearch_")), key=key)
    if not os_versions:
        raise AssertionError(f"no OpenSearch_* engine version offered: {versions!r}")
    return os_versions[-1]


def _minimal_domain_kwargs(domain_name, *, engine_version) -> dict:
    return dict(
        DomainName=domain_name,
        EngineVersion=engine_version,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        TagList=[{"Key": "sim2real:check", "Value": CHECK}],
    )


def _create_domain(ctx, osc, domain_name, *, engine_version) -> dict:
    kwargs = _minimal_domain_kwargs(domain_name, engine_version=engine_version)
    for _attempt in range(12):
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until Processing=False and Created=True; a domain needs 10-20 min to go Active."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} never became Active within {budget}s",
    )


def _retry_on(fn, *, error_codes=(), message_substrings=(), attempts=6, delay_s=10.0):
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if attempt < attempts - 1 and (
                code in error_codes or any(s in msg for s in message_substrings)
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _error(fn) -> "tuple[str, str]":
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIndex->GetIndex->UpdateIndex->DeleteIndex on a live domain: GetIndex reflects the
    created and updated schema, and after deletion GetIndex and UpdateIndex both fail with
    ResourceNotFoundException and the exact not-found message."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain, engine_version=_pick_latest_opensearch_version(osc))
    _wait_domain_active(ctx, osc, domain)

    idx = ctx.unique_name("sim2real-behav-idx-").lower()
    schema_v1 = {"mappings": {"properties": {"title": {"type": "text"}}}}
    create_resp = _retry_on(
        lambda: osc.create_index(DomainName=domain, IndexName=idx, IndexSchema=schema_v1),
        error_codes=("DependencyFailureException",),
        message_substrings=("not available now",),
    )
    assert create_resp["Status"] in ("CREATED",)

    # GetIndex's IndexSchema echo can restructure nesting vs the request body, so assert on
    # field names present rather than an exact path.
    got = osc.get_index(DomainName=domain, IndexName=idx)
    assert "IndexSchema" in got
    dumped_v1 = json.dumps(got["IndexSchema"])
    assert '"title"' in dumped_v1 and '"text"' in dumped_v1, (
        f"unexpected schema shape: {got['IndexSchema']!r}"
    )

    schema_v2 = {"mappings": {"properties": {"title": {"type": "text"}, "body": {"type": "text"}}}}
    update_resp = osc.update_index(DomainName=domain, IndexName=idx, IndexSchema=schema_v2)
    assert update_resp["Status"] in ("UPDATED",)

    got2 = osc.get_index(DomainName=domain, IndexName=idx)
    dumped_v2 = json.dumps(got2["IndexSchema"])
    assert '"body"' in dumped_v2, f"update not reflected in schema: {got2['IndexSchema']!r}"

    osc.delete_index(DomainName=domain, IndexName=idx)
    code, message = _error(lambda: osc.get_index(DomainName=domain, IndexName=idx))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Resource index {idx} does not exist", f"unexpected GetIndex not-found message: {message!r}"

    # A mutation on the deleted index fails the same way a read does.
    update_code, update_message = _error(
        lambda: osc.update_index(DomainName=domain, IndexName=idx, IndexSchema=schema_v2)
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateIndex on a deleted index to fail ResourceNotFoundException, got {update_code!r}"
    )
    assert update_message == f"Resource index {idx} does not exist", (
        f"unexpected UpdateIndex not-found message: {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

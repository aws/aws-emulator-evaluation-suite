"""delete-rest-api-racing-base-path-mapping-leaves-orphaned-mapping."""
from __future__ import annotations

import random
import string
import subprocess
import tempfile
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-rest-api-racing-base-path-mapping-leaves-orphaned-mapping"
GROUP = 'state-machine'
SERVICES = ['apigateway']


def _delete_domain_name_settled(apigw, domain: str, *, timeout_s: float = 420.0, interval_s: float = 15.0) -> None:
    """Teardown: retry while API Gateway reports an update in progress or throttles the delete; a
    domain name already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.delete_domain_name(domainName=domain)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "NotFoundException":
                return
            busy = error["Code"] == "TooManyRequestsException" or (
                error["Code"] == "BadRequestException" and "update in progress" in error.get("Message", "").lower()
            )
            if not busy or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_certificate_released(acm, arn: str, *, timeout_s: float = 420.0, interval_s: float = 15.0) -> None:
    """Teardown: API Gateway releases a deleted domain name's certificate some time after the
    delete, so retry while ACM reports it in use; a certificate already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_mapping(ag, domain: str, base_path: str) -> None:
    """Teardown: delete the mapping; one gone, or orphaned by its deleted RestApi, is fine."""
    try:
        ag.delete_base_path_mapping(domainName=domain, basePath=base_path)
    except ClientError as exc:
        error = exc.response["Error"]
        orphaned = error["Code"] == "BadRequestException" and error.get("Message") == "Invalid REST API identifier specified"
        if error["Code"] != "NotFoundException" and not orphaned:
            raise


def _error(fn):
    """Call fn(); return the botocore Error (code, message), or ("SUCCEEDED", None) on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    return "SUCCEEDED", None

def _err_code(result):
    """Extract the botocore error code from a run_concurrent() result slot, or the
    exception's class name for another exception type, or None for a success."""
    if isinstance(result, ClientError):
        return result.response.get("Error", {}).get("Code")
    if isinstance(result, BaseException):
        return type(result).__name__
    return None

def _assert_refusal(result, bad_request_message):
    """Grade a losing racer exactly: BadRequestException with bad_request_message, or a throttle
    with API Gateway's 'Too Many Requests'. Returns the code."""
    assert isinstance(result, ClientError), f"expected the losing call to be refused, got {result!r}"
    error = result.response.get("Error", {})
    code, message = error.get("Code"), error.get("Message")
    if code == "TooManyRequestsException":
        assert message == "Too Many Requests", f"unexpected TooManyRequestsException message {message!r}"
    else:
        assert code == "BadRequestException", f"unexpected refusal {code}: {message!r}"
        assert message == bad_request_message, f"unexpected BadRequestException message {message!r}"
    return code


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _put_mock_method(ag, api_id, resource_id, http_method="GET"):
    """A fully integrated MOCK method (deployable without a real backend)."""
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                  authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                       type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                           statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                                statusCode="200", responseTemplates={"application/json": '{"message": "ok"}'})

def _import_self_signed_certificate(ctx, common_name):
    """Generate an ephemeral self-signed cert via the system openssl CLI and
    ACM-import it (import is instant). Returns the CertificateArn (teardown
    registered)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = f"{d}/key.pem"
        cert_path = f"{d}/cert.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-keyout", key_path,
             "-out", cert_path, "-days", "2", "-subj", f"/CN={common_name}"],
            check=True, capture_output=True, timeout=30,
        )
        with open(cert_path) as f:
            cert_pem = f.read()
        with open(key_path) as f:
            key_pem = f.read()
    acm = ctx.client("acm")
    arn = acm.import_certificate(
        Certificate=cert_pem.encode("utf-8"), PrivateKey=key_pem.encode("utf-8"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_released(acm, arn))
    return arn

def _delete_rest_api_settled(ag, api_id: str, *, timeout_s: float = 240.0, interval_s: float = 10.0) -> None:
    """Delete the RestApi, retrying while API Gateway throttles the delete (its per-account delete
    rate is low); a RestApi already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _deployable_rest_api(ctx, ag, prefix):
    """A REGIONAL RestApi with one MOCK method deployed to a stage; returns (api_id, stage_name)
    (teardown registered)."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name(prefix),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_settled(ag, api_id))
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="res")["id"]
    _put_mock_method(ag, api_id, resource_id)
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage_name = f"s{_unique_token()}"
    ag.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    return api_id, stage_name


def _rounds_deadline(ctx, cap_s):
    """When the last race round may start: cap_s from now, bounded by the runner's remaining time
    less 150 s for the orphan assertions and the teardown."""
    left = ctx.time_left()
    return time.monotonic() + (cap_s if left is None else max(0.0, min(cap_s, left - 150.0)))


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)

    # The racers leave together: each waits at a barrier before sending its request.
    barrier = threading.Barrier(len(fns))

    def _released(fn):
        barrier.wait(timeout=timeout_s)
        return fn()

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(_released, fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Race CreateBasePathMapping(A) against DeleteRestApi(A), re-armed until both win: the mapping is
    not cascade-deleted and still blocks its slot for a second RestApi (ConflictException); a round's
    loser gets its exact refusal."""
    ag = ctx.client("apigateway")
    domain = f"{ctx.unique_name('sim2real-behav-mapdom-')}.example.com"
    cert_arn = _import_self_signed_certificate(ctx, domain)
    ag.create_domain_name(
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_domain_name_settled(ag, domain))

    # A serialized pair has one loser, so a round where one call lost re-arms the race on a fresh
    # base path (and a fresh RestApi once the delete won), up to _ROUNDS and the run budget.
    deadline = _rounds_deadline(ctx, 240.0)
    outcomes = []
    api_id = None
    for round_no in range(_ROUNDS):
        if api_id is None:
            api_id, stage_name = _deployable_rest_api(ctx, ag, "sim2real-behav-apigw-")
        base_path = f"v{round_no + 1}"

        def _create_mapping(api_id=api_id, stage_name=stage_name, base_path=base_path):
            return ag.create_base_path_mapping(
                domainName=domain, basePath=base_path, restApiId=api_id, stage=stage_name
            )

        def _delete_api(api_id=api_id):
            return ag.delete_rest_api(restApiId=api_id)

        mapping_result, delete_result = _run_concurrent([_create_mapping, _delete_api])
        mapping_ok = not isinstance(mapping_result, BaseException)
        delete_ok = not isinstance(delete_result, BaseException)
        outcomes.append((base_path, _err_code(mapping_result), _err_code(delete_result)))

        assert mapping_ok or delete_ok, (
            f"expected at least one contender to win, but both failed: "
            f"mapping={mapping_result!r} delete={delete_result!r}"
        )
        if mapping_ok:
            # Registered after the domain and RestApi cleanups so LIFO teardown removes the
            # mapping BEFORE the RestApi it references. A mapping orphaned by the RestApi delete
            # refuses its own delete as BadRequest naming the RestApi; the domain name's delete
            # removes it.
            ctx.on_cleanup(lambda base_path=base_path: _delete_mapping(ag, domain, base_path))
        if mapping_ok and delete_ok:
            break

        if delete_ok:
            # The delete won outright: the losing CreateBasePathMapping is refused because the
            # restApiId no longer resolves, or throttled away; each answer is graded exactly.
            _assert_refusal(mapping_result, "Invalid REST API identifier specified")
            api_id = None
        else:
            # The mapping won outright: DeleteRestApi is refused while the mapping references
            # the RestApi, or throttled away; each answer is graded exactly.
            delete_code = _assert_refusal(
                delete_result,
                f"Deleting RestApi {api_id} failed. Please remove all base path mappings related "
                f"to the RestApi in your domains: {domain}",
            )
            # The RestApi stays for the next round once this round's mapping is gone; after a
            # throttled delete it is deleted once the delete rate admits it, so the next round's
            # racing delete is not throttled too.
            ag.delete_base_path_mapping(domainName=domain, basePath=base_path)
            if delete_code == "TooManyRequestsException":
                _delete_rest_api_settled(ag, api_id)
                api_id = None
        if time.monotonic() >= deadline:
            break
    assert mapping_ok and delete_ok, (
        f"expected a round where both CreateBasePathMapping and DeleteRestApi succeed, "
        f"got (basePath, mapping error, delete error) per round: {outcomes}"
    )

    # Both won: independently confirm the RestApi is gone (bounded retry --
    # DeleteRestApi is itself async, a 202) ...
    api_gone = False
    gone_deadline = time.time() + 10
    while time.time() < gone_deadline:
        error, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
        if error != "SUCCEEDED":
            assert error == "NotFoundException", (
                f"expected GetRestApi on a deleted RestApi to fail with "
                f"NotFoundException, got {error}"
            )
            account_id = cert_arn.split(":")[4]
            assert message == f"Invalid API identifier specified {account_id}:{api_id}", message
            api_gone = True
            break
        time.sleep(1)
    assert api_gone, "expected GetRestApi to report the deleted RestApi gone within 10s"

    # ... then confirm the mapping is NOT torn down with it. Real API Gateway
    # does not cascade-delete a BasePathMapping when the RestApi it references
    # is deleted.
    mappings = ag.get_base_path_mappings(domainName=domain)["items"]
    mapping_present = any(m["basePath"] == base_path for m in mappings)
    assert mapping_present, (
        "expected the BasePathMapping created just before DeleteRestApi resolved "
        "to remain listed -- real API Gateway does not cascade-delete a "
        "BasePathMapping when the RestApi it references is deleted "
        f"(mapping={mapping_result!r} delete={delete_result!r})"
    )

    # Map the slot to a second, live RestApi: reusing the deleted api_id returns
    # BadRequestException, which would not prove the slot is still occupied.
    api_id2, stage_name2 = _deployable_rest_api(ctx, ag, "sim2real-behav-apigw2-")
    conflict_code, conflict_message = _error(lambda: ag.create_base_path_mapping(
        domainName=domain, basePath=base_path, restApiId=api_id2, stage=stage_name2
    ))
    assert conflict_code == "ConflictException", (
        f"expected mapping the occupied (domain, basePath) to a second, live "
        f"RestApi to be rejected while the orphaned mapping still occupies the "
        f"slot, got {conflict_code}"
    )
    assert conflict_message == "Base path already exists for this domain name", conflict_message


_ROUNDS = 5


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

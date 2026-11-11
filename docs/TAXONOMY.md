# Taxonomy

Each row of `manifest.jsonl` carries labels from these namespaces.

## `plane`

Which plane the operation the assertion is about belongs to; a rejection belongs to the plane of the rejected call. A test carries both values when it asserts on both, such as a refused configuration and its effect on data.

- `plane:control`: The assertion is about configuring AWS resources: creating, updating, deleting, or describing them, or evaluating a policy without using a resource (ValidatePolicy, SimulatePrincipalPolicy, an access preview). A rejected configuration call, such as a malformed PutBucketPolicy, is control.
- `plane:data`: The assertion is about using AWS resources: data being written, stored, or read back; messages sent; or functions invoked. A rejected or denied use, such as a GetObject denied by a bucket policy or a Decrypt without a grant, is data. Requires one or more `dp` values naming the data planes.

## `dp`

Which data planes a data-plane test reaches; absent on a control-plane test.

- `dp:api`: The signed AWS API is the data plane (S3 PutObject, SQS SendMessage, KMS Decrypt).
- `dp:native`: The test speaks a non-AWS wire protocol (a database, cache, message-broker, search, or container-orchestration protocol, or a shell on a guest instance) with a native client, driver, or command-line tool.
- `dp:endpoint`: The test contacts a non-AWS-API hostname over HTTP or a socket, such as a GET through a CloudFront distribution or an API Gateway stage, or a load-balancer request.

## `axis`

Which kind of outcome the test asserts; exactly one per test.

- `axis:rejection`: A negative test: AWS rejects the request, and the emulator must too, with the same error code and unchanged state. A function error returned by a successful invocation is not a rejection.
- `axis:happy-path`: A positive test: the operation succeeds, and its observable outcome matches AWS.
- `axis:negative-delivery`: A delivery negative: the emulator must not deliver, and the assertion is an absence observed at the destination (a non-matching event never arrives, a filtered record is not written). A synchronous call refused with an error code is `rejection`.

## `timing`

Whether the test waits out an AWS-defined period; absent when it waits only on conditions.

- `timing:real-time`: The test waits out an AWS-defined period (a TTL, a schedule, a metric or alarm period, a delivery buffer, a cooldown), so the runner gives it 600 s instead of 60 s.

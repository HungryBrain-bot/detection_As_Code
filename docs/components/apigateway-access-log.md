# API Gateway access log format (rules D6 and E10)

Defined by this project (ADR 014). API Gateway has no fixed access log
format: each stage's owner writes one from `$context` variables. Rules
D6 and E10 read the keys below, so every API stage they cover must log
this JSON, one object per line. Nothing here is a vendor schema; the
`$context` variables are AWS's, checked on the two AWS pages listed
under Sources.

## Format

REST APIs (stage > Logs and tracing > Custom access logging, or
`accessLogSettings.format`):

```json
{"requestId":"$context.requestId","requestTimeEpoch":"$context.requestTimeEpoch","apiId":"$context.apiId","stage":"$context.stage","domainName":"$context.domainName","sourceIp":"$context.identity.sourceIp","userAgent":"$context.identity.userAgent","httpMethod":"$context.httpMethod","path":"$context.path","route":"$context.resourcePath","status":"$context.status","responseLength":"$context.responseLength","authorizerError":"$context.authorizer.error","errorType":"$context.error.responseType","user":"$context.authorizer.claims.sub"}
```

HTTP APIs: the same, with `"route":"$context.routeKey"`.

`user` depends on how the API authenticates. Cognito user pool and JWT
authorizers: `$context.authorizer.claims.sub` (as above). REST Lambda
authorizers: `$context.authorizer.principalId`. IAM authorization:
`$context.identity.userArn` (HTTP APIs) or `$context.identity.user`.
Unauthenticated APIs: leave it out; the rules then key on the address
alone.

| Key | `$context` variable | AWS description (fetched 2026-11-21) | Read by |
|---|---|---|---|
| `requestTimeEpoch` | `requestTimeEpoch` | REST: "The Epoch-formatted request time, in milliseconds." HTTP: "The Epoch-formatted request time." (no unit given) | D6, E10 (window) |
| `apiId`, `stage` | `apiId`, `stage` | "The identifier API Gateway assigns to your API."; "The deployment stage of the API request" | D6, E10 (filter, report) |
| `domainName` | `domainName` | "The full domain name used to invoke the API. This should be the same as the incoming Host header." | D6, E10 (host) |
| `sourceIp` | `identity.sourceIp` | "The source IP address of the immediate TCP connection making the request to the API Gateway endpoint." | D6, E10 (client) |
| `userAgent` | `identity.userAgent` | "The User-Agent header of the API caller." | report |
| `path` | `path` | "The request path." Example `/{stage}/root/child` | D6, E10 |
| `route` | `resourcePath` / `routeKey` | "The path to your resource." / "The route key of the API request" | report |
| `status` | `status` | "The method response status." | D6, E10 |
| `responseLength` | `responseLength` | "The response payload length in bytes." | E10 (volume) |
| `authorizerError`, `errorType` | `authorizer.error`, `error.responseType` | "The error message returned from an authorizer."; "A type of GatewayResponse." | report |
| `user` | see above | "a property of the claims returned from" the authorizer (paraphrased) | E10 (client) |

## How it reaches Sentinel
API Gateway writes access logs to a CloudWatch Logs log group (AWS:
"Access log destination ARN"). Sentinel's AWS S3 connector reads
"AWS CloudWatch - CloudWatch logs" from S3 into `AWSCloudWatch`; the
log group must be copied to S3 first. Microsoft provides two Lambda
functions for that (Azure-Sentinel c3361d9,
`DataConnectors/AWS-S3/CloudWatchLambdaFunction.py`, a one-off export of
a fixed time window, and `CloudWatchPushBasedLambdaFunction.py`, driven
by a CloudWatch Logs subscription). Both write each log event's
`message` as one line, so `AWSCloudWatch.Message` is the JSON above.
Use the subscription one: the export one stops at its configured end
time.

Not verified: the pipeline end to end (no AWS account or workspace
here); whether `TimeGenerated` is the request time or the ingestion
time (Microsoft's Lambda drops CloudWatch's timestamp, and Learn says
`TimeGenerated` falls back to ingestion time). The rules window on
`requestTimeEpoch` for that reason.

## What the format does not give
- **The query string.** Neither AWS page lists a variable for the
  incoming query string. E10 cannot read record IDs from `?id=`; E1 on
  App Service can.
- **Values API Gateway has no value for.** How an empty variable is
  written (empty, `-`, or the key dropped) was not found on the AWS
  pages; the rules treat empty and `-` alike.
- **Which rejected requests are logged.** Whether a request to a path
  with no matching resource (REST "Missing Authentication Token", HTTP
  API 404), or one refused by WAF or throttling, appears in the access
  log was not found on the AWS pages read. D6 counts 401, 403 and 404
  whichever produce them.

## Sources
- AWS, "Variables for access logging for API Gateway" (REST APIs),
  https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-variables-for-access-logging.html
- AWS, "Customize HTTP API access logs",
  https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging-variables.html
- AWS, "Set up CloudWatch logging for REST APIs in API Gateway",
  https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html
- Microsoft Learn, "Connect Microsoft Sentinel to Amazon Web Services to
  ingest AWS service log data", https://learn.microsoft.com/en-us/azure/sentinel/connect-aws,
  and the AWSCloudWatch table reference.
- Azure-Sentinel repository, commit c3361d9, the two Lambda files above
  (read directly with git).
All AWS and Learn pages fetched 2026-11-21 through a fetch tool.

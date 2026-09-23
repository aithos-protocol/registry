# References and licenses

- [A2A 1.0 specification](https://a2a-protocol.org/v1.0.0/specification/): extension
  negotiation and binding-specific errors. This pilot follows the partner's
  currently implemented subset, not all transports and task operations.
- [A2A extension model](https://a2a-protocol.org/dev/topics/extensions/).
- [HTTP Message Signatures, RFC 9421](https://www.rfc-editor.org/rfc/rfc9421).
- [Digest Fields, RFC 9530](https://www.rfc-editor.org/rfc/rfc9530).
- [JWK Thumbprints, RFC 7638](https://www.rfc-editor.org/rfc/rfc7638).
- [structured-headers](https://github.com/evert/structured-headers), BSD-3-Clause:
  structured-field parser and serializer. Node crypto supplies cryptography;
  Aithos does not implement the elliptic-curve primitive.
- Local `agent-request-auth` v2 source snapshot
  `1583c1746b0df258c959d14b38c45c5e9042e09d`, Apache-2.0. The files
  `tests/vectors/profile-v2.json` and `tests/vectors/rfc9421-b24.json` are copied
  from that project. Vectors are public test material, not deployment secrets.
- [Shopware sales-agent-harness](https://github.com/agentic-commerce-lab/sales-agent-harness),
  MIT, upstream snapshot `51efcee7d7680f8e3fe8444a4dbed029129caf94`.
- [DynamoDB transaction IAM](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html):
  only the underlying table operations are granted to the Lambda role.

No A2A SDK client or agent execution framework is added to Aithos in this pilot.
Maintained libraries used: AWS SDK v3, Zod, structured-headers, Node crypto and
Bun SQLite. The partner's existing runtime/dependency selection is unchanged.

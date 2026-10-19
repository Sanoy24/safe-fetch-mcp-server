## What and why

<!-- One or two sentences. Link the issue it addresses. -->

## Security checklist

- [ ] No new outbound request path — every fetch still goes through `safeFetch` in `src/security/`.
- [ ] Any change to URL/DNS/IP/redirect handling has a failing-first regression test.
- [ ] No security control weakened or bypassed to make a test pass.
- [ ] Refusal messages stay actionable and don't leak internal addresses or stack traces.

## Checks

- [ ] `npm run check` passes locally (format, lint, typecheck, build, test).
- [ ] CHANGELOG updated if behaviour or public output changed.

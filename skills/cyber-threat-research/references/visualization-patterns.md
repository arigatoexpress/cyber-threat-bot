# Visualization Patterns

Use visuals to clarify mechanics, not to decorate the answer.

## Flowchart

```mermaid
flowchart LR
  input["Untrusted input"] --> parser["Parser / validator"]
  parser --> decision{"Boundary check?"}
  decision -->|passes| sink["Sensitive code path"]
  decision -->|fails| reject["Rejected input"]
```

Use this for parser flaws, auth bypass, request routing, and trust-boundary explanations.

## Sequence Diagram

```mermaid
sequenceDiagram
  participant U as User
  participant A as App
  participant P as Parser
  participant S as Sensitive Service
  U->>A: Send crafted request
  A->>P: Normalize and validate
  P-->>A: Incorrect safe/unsafe decision
  A->>S: Forward privileged action
```

Use this when interaction order matters more than memory layout.

## ASCII Memory or Packet Layout

```text
0x00  [ len_lo ][ len_hi ]
0x02  [ flags  ][ type   ]
0x04  [ user-controlled data............. ]
```

Use this for serialized objects, binary protocols, heap chunks, and frame layouts.

## Labeling rules

- Mark sourced visuals as `Observed` when tied to a public artifact or specification.
- Mark unsourced teaching visuals as `Illustrative`.
- Never present an illustrative byte sketch as if it were a captured exploit sample.


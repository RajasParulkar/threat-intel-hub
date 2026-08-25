# Defense & Cyber Threat Intelligence Hub (Java / Spring Boot)

Converts news reports and cyber advisories into structured, STIX-style threat intelligence cards.

## Modules
1. `RedactionService` — local pre-processing. Strips IPv4 addresses, emails, internal
   hostnames (`*.local/.internal/.intranet/.lan/.corp`) and phone numbers **before**
   any text leaves the server. Originals stay in an in-memory token map.
2. `IntelExtractionService` — extraction engine. Detects threat actor, target system,
   CVEs, computes a severity score and generates action items, then emits a minimal
   STIX 2.1 bundle.
3. `IntelController` + `static/index.html` — REST API and single-page UI (threat cards + feed).

## Run in VS Code
Install the "Extension Pack for Java" + JDK 17, then:

```bash
mvn spring-boot:run
```

Open http://localhost:8080

## API
- `POST /api/redact`  `{ "text": "..." }` → sanitized text + redaction findings
- `POST /api/analyze` `{ "text": "..." }` → threat card JSON (with `stixBundle`)
- `GET  /api/feed` → all generated cards

## Plugging in a real LLM
Keep the JSON schema of `ThreatCard`. In `IntelExtractionService.analyse`, send
`red.sanitizedText` to your model with a prompt that forces JSON:

```
Return ONLY JSON: {"threatActor":"","targetSystem":"","severity":"LOW|MEDIUM|HIGH|CRITICAL",
"summary":"","actionItems":[""],"cves":[""]}
```

Parse it into `ThreatCard` and keep `toStix(card)` for the STIX output. The rule-based
path stays as the offline fallback so the demo never fails.

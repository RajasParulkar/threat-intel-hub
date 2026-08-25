package com.dcti.hub;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class IntelController {

    private final RedactionService redaction;
    private final IntelExtractionService extraction;
    private final List<ThreatCard> feed = Collections.synchronizedList(new ArrayList<>());

    public IntelController(RedactionService redaction, IntelExtractionService extraction) {
        this.redaction = redaction;
        this.extraction = extraction;
    }

    /** Step 1: preview what the redaction engine strips before AI is called. */
    @PostMapping("/redact")
    public Map<String, Object> preview(@RequestBody Map<String, String> body) {
        RedactionService.RedactionResult r = redaction.redact(body.get("text"));
        return Map.of("sanitizedText", r.sanitizedText, "findings", r.findings);
    }

    /** Step 2: full pipeline -> structured STIX-style threat card. */
    @PostMapping("/analyze")
    public ThreatCard analyze(@RequestBody Map<String, String> body) {
        RedactionService.RedactionResult r = redaction.redact(body.get("text"));
        ThreatCard card = extraction.analyse(body.get("text"), r);
        feed.add(0, card);
        return card;
    }

    /** The generated intelligence feed. */
    @GetMapping("/feed")
    public List<ThreatCard> feed() {
        return feed;
    }
}

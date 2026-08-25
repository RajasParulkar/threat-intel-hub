package com.dcti.hub;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Module 1: Pre-processing / Redaction engine.
 * Runs 100% locally BEFORE any text is sent to an AI model.
 * Sensitive IPs, emails and internal hostnames are replaced with stable tokens.
 */
@Service
public class RedactionService {

    private static final Pattern IPV4 =
            Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern EMAIL =
            Pattern.compile("\\b[\\w.+-]+@[\\w-]+\\.[\\w.-]{2,}\\b");
    // internal server names: srv-db01.corp.local, dc1.internal, host.intranet ...
    private static final Pattern INTERNAL_HOST =
            Pattern.compile("\\b[\\w-]+(?:\\.[\\w-]+)*\\.(?:local|internal|intranet|lan|corp)\\b",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern PHONE =
            Pattern.compile("\\+?\\d[\\d\\s-]{8,13}\\d");

    public static class RedactionResult {
        public String sanitizedText;
        /** token -> original value. NEVER leaves the server. */
        public Map<String, String> mapping = new LinkedHashMap<>();
        public List<String> findings = new ArrayList<>();
    }

    public RedactionResult redact(String raw) {
        RedactionResult r = new RedactionResult();
        String text = raw == null ? "" : raw;

        text = mask(text, EMAIL, "EMAIL", r);
        text = mask(text, INTERNAL_HOST, "INTERNAL_HOST", r);
        text = mask(text, IPV4, "IP", r);
        text = mask(text, PHONE, "PHONE", r);

        r.sanitizedText = text;
        return r;
    }

    private String mask(String text, Pattern p, String label, RedactionResult r) {
        Matcher m = p.matcher(text);
        StringBuilder out = new StringBuilder();
        int counter = 1;
        while (m.find()) {
            String original = m.group();
            String token = "[" + label + "_" + counter++ + "]";
            r.mapping.put(token, original);
            r.findings.add(label + " redacted");
            m.appendReplacement(out, Matcher.quoteReplacement(token));
        }
        m.appendTail(out);
        return out.toString();
    }
}

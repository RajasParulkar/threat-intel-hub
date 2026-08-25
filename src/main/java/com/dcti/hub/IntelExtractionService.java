package com.dcti.hub;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Module 2: extraction engine.
 * This offline rule-based extractor is the prototype fallback so the app runs
 * with zero API keys. Swap buildCard(...) for an LLM call (see callLlm below)
 * and keep the same JSON schema.
 */
@Service
public class IntelExtractionService {

    private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,7}", Pattern.CASE_INSENSITIVE);

    private static final String[] ACTORS = {
            "APT28", "APT29", "APT41", "Lazarus", "Sandworm", "Fancy Bear",
            "LockBit", "BlackCat", "Cl0p", "Kimsuky", "Mustang Panda"
    };

    private static final String[] TARGETS = {
            "SCADA", "ICS", "OT network", "Active Directory", "VPN gateway",
            "Exchange Server", "Linux server", "Windows workstation",
            "cloud infrastructure", "banking systems", "defence network",
            "power grid", "router", "firewall"
    };

    public ThreatCard analyse(String rawText, RedactionService.RedactionResult red) {
        String text = red.sanitizedText;
        String lower = text.toLowerCase(Locale.ROOT);

        ThreatCard card = new ThreatCard();
        card.id = "card-" + UUID.randomUUID();
        card.sanitizedInput = text;
        card.redactionFindings = red.findings;
        card.title = firstSentence(text);
        card.threatActor = findFirst(text, ACTORS, "Unattributed");
        card.targetSystem = findFirst(text, TARGETS, "Unspecified systems");
        card.cves = matchAll(text, CVE);
        card.severity = scoreSeverity(lower, card.cves.size());
        card.summary = summarise(text);
        card.actionItems = actionItems(lower, card);
        card.stixBundle = toStix(card);
        return card;
    }

    private String scoreSeverity(String lower, int cveCount) {
        int score = 0;
        if (contains(lower, "zero-day", "zero day", "actively exploited", "in the wild")) score += 3;
        if (contains(lower, "ransomware", "wiper", "data exfiltration", "critical infrastructure")) score += 2;
        if (contains(lower, "remote code execution", "rce", "privilege escalation")) score += 2;
        if (contains(lower, "denial of service", "phishing", "scanning")) score += 1;
        score += Math.min(cveCount, 2);
        if (score >= 6) return "CRITICAL";
        if (score >= 4) return "HIGH";
        if (score >= 2) return "MEDIUM";
        return "LOW";
    }

    private List<String> actionItems(String lower, ThreatCard card) {
        List<String> items = new ArrayList<>();
        if (!card.cves.isEmpty()) items.add("Patch affected systems for " + String.join(", ", card.cves));
        if (contains(lower, "phishing", "email")) items.add("Push a phishing advisory to all users and tighten mail filtering");
        if (contains(lower, "ransomware", "wiper")) items.add("Verify offline backups and test restore procedure");
        if (contains(lower, "vpn", "firewall", "gateway")) items.add("Review perimeter device logs and enforce MFA on remote access");
        if (contains(lower, "scada", "ics", "ot")) items.add("Confirm IT/OT segmentation and disable unused remote engineering access");
        items.add("Ingest published IOCs into SIEM and hunt for the last 30 days");
        if ("CRITICAL".equals(card.severity) || "HIGH".equals(card.severity)) {
            items.add("Escalate to the incident response duty officer within 4 hours");
        }
        return items;
    }

    private Map<String, Object> toStix(ThreatCard card) {
        List<Map<String, Object>> objects = new ArrayList<>();
        String now = Instant.now().toString();

        Map<String, Object> actor = new LinkedHashMap<>();
        actor.put("type", "threat-actor");
        actor.put("id", "threat-actor--" + UUID.randomUUID());
        actor.put("created", now);
        actor.put("name", card.threatActor);
        objects.add(actor);

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("type", "report");
        report.put("id", "report--" + UUID.randomUUID());
        report.put("created", now);
        report.put("name", card.title);
        report.put("description", card.summary);
        report.put("labels", List.of("threat-report", card.severity.toLowerCase(Locale.ROOT)));
        report.put("object_refs", List.of(actor.get("id")));
        objects.add(report);

        for (String cve : card.cves) {
            Map<String, Object> vuln = new LinkedHashMap<>();
            vuln.put("type", "vulnerability");
            vuln.put("id", "vulnerability--" + UUID.randomUUID());
            vuln.put("created", now);
            vuln.put("name", cve.toUpperCase(Locale.ROOT));
            objects.add(vuln);
        }

        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("type", "bundle");
        bundle.put("id", "bundle--" + UUID.randomUUID());
        bundle.put("spec_version", "2.1");
        bundle.put("objects", objects);
        return bundle;
    }

    // ---------- helpers ----------

    private boolean contains(String lower, String... needles) {
        for (String n : needles) if (lower.contains(n)) return true;
        return false;
    }

    private String findFirst(String text, String[] candidates, String fallback) {
        String lower = text.toLowerCase(Locale.ROOT);
        for (String c : candidates) {
            if (lower.contains(c.toLowerCase(Locale.ROOT))) return c;
        }
        return fallback;
    }

    private List<String> matchAll(String text, Pattern p) {
        List<String> out = new ArrayList<>();
        Matcher m = p.matcher(text);
        while (m.find()) {
            String v = m.group().toUpperCase(Locale.ROOT);
            if (!out.contains(v)) out.add(v);
        }
        return out;
    }

    private String firstSentence(String text) {
        String t = text.trim().replaceAll("\\s+", " ");
        int dot = t.indexOf(". ");
        String s = dot > 20 ? t.substring(0, dot) : t;
        return s.length() > 120 ? s.substring(0, 120) + "..." : s;
    }

    private String summarise(String text) {
        String t = text.trim().replaceAll("\\s+", " ");
        String[] parts = t.split("(?<=\\.)\\s+");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(3, parts.length); i++) sb.append(parts[i]).append(' ');
        return sb.toString().trim();
    }
}

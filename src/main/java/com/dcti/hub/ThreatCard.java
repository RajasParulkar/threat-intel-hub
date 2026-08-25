package com.dcti.hub;

import java.util.List;
import java.util.Map;

/** Module 3: the structured JSON card returned to the UI. */
public class ThreatCard {
    public String id;
    public String title;
    public String threatActor;
    public String targetSystem;
    public String severity;          // LOW | MEDIUM | HIGH | CRITICAL
    public String summary;
    public List<String> actionItems;
    public List<String> cves;
    public List<String> redactionFindings;
    /** minimal STIX 2.1 bundle representation */
    public Map<String, Object> stixBundle;
    public String sanitizedInput;
}

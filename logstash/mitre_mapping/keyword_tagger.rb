# frozen_string_literal: true
#
# Keyword tagger: annotate each event with the DataComponent keywords that
# appear in its *log message body*.
#
# Design notes
# ------------
# Earlier versions of this filter scanned the full stringified event
# (``message`` + every field concatenated) with an unbounded ``include?``
# substring match.  That produced two systematic classes of false positives
# downstream:
#
#   1. Vendor tokens carried in routing metadata (``log.file.path`` contains
#      ``tomcat``, ``container.name`` contains ``openplc``) tagged every
#      benign boot / heartbeat line with DC-specific keywords.
#   2. Short digit tokens (Windows Event IDs such as ``41`` or ``5156``)
#      substring-matched inside unrelated machine identifiers (``flow_id``,
#      ``log.offset``, byte counters, timestamps).
#
# Both classes inflated the engine's keyword-signal score on events that
# had no narrative relationship to the DC.  Keyword evidence should reflect
# what the monitored system *said*, not how the pipeline routes it, so this
# filter now:
#
#   * scans only the log-message body (``log_message`` / ``message``);
#   * refuses tokens shorter than 2 characters;
#   * uses word-boundary-aware matching (digits must be whole-number runs,
#     alphabetic tokens must not be substrings of longer words);
#   * preserves the original keyword casing in the emitted hit list.
#
# The engine re-validates anchoring independently, so this change is a
# defence-in-depth alignment rather than a behaviour change relied upon in
# isolation.

require "json"

BOUNDARY_CHARS = /[A-Za-z0-9_]/.freeze

def register(params)
  @keywords_path = params["keywords_path"]
  @dc_keywords = {}
  begin
    @dc_keywords = JSON.parse(File.read(@keywords_path))
  rescue StandardError => e
    @dc_keywords = {}
    @logger.error("Failed loading dc keywords file", :path => @keywords_path, :error => e.message)
  end
end

def filter(event)
  body = (event.get("log_message") || event.get("message") || "").to_s.downcase
  return [event] if body.empty?

  hits = {}
  @dc_keywords.each do |dc_id, words|
    next unless words.is_a?(Array)

    matched = []
    seen = {}
    words.each do |w|
      raw = w.to_s.strip
      next if raw.length < 2
      next if seen[raw.downcase]
      seen[raw.downcase] = true
      matched << w if keyword_in_body?(raw.downcase, body)
    end
    hits[dc_id] = matched unless matched.empty?
  end

  unless hits.empty?
    event.set("mitre_keyword_hits", hits)
    event.tag("mitre_keyword_match")
  end

  [event]
end

def keyword_in_body?(kw, body)
  return false if kw.nil? || kw.empty?

  if kw =~ /\A\d+\z/
    # Digit-only keyword: must appear as a whole-number run.
    return false unless body.include?(kw)
    idx = 0
    while (pos = body.index(kw, idx))
      before = pos.zero? ? "" : body[pos - 1, 1]
      after_pos = pos + kw.length
      after = after_pos >= body.length ? "" : body[after_pos, 1]
      return true unless before =~ /\d/ || after =~ /\d/
      idx = pos + 1
    end
    return false
  end

  # Alphabetic / mixed: word-boundary match against ASCII word chars.
  return false unless body.include?(kw)
  idx = 0
  while (pos = body.index(kw, idx))
    before = pos.zero? ? "" : body[pos - 1, 1]
    after_pos = pos + kw.length
    after = after_pos >= body.length ? "" : body[after_pos, 1]
    left_ok = before.empty? || before !~ BOUNDARY_CHARS
    right_ok = after.empty? || after !~ BOUNDARY_CHARS
    return true if left_ok && right_ok
    idx = pos + 1
  end
  false
end

# frozen_string_literal: true

require "json"

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
  message = (event.get("log_message") || event.get("message") || "").downcase
  fields = event.to_hash.map { |k, v| "#{k}=#{v}" }.join(" ").downcase
  haystack = "#{message} #{fields}"

  hits = {}
  @dc_keywords.each do |dc_id, words|
    next unless words.is_a?(Array)

    matched = []
    words.each do |w|
      kw = w.to_s.strip.downcase
      next if kw.empty?
      matched << w if haystack.include?(kw)
    end
    hits[dc_id] = matched unless matched.empty?
  end

  unless hits.empty?
    event.set("mitre_keyword_hits", hits)
    event.tag("mitre_keyword_match")
  end

  [event]
end

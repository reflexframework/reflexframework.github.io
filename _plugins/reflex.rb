# frozen_string_literal: true

# Jekyll Liquid block to inject HTML before and after a section of text.
# Usage in Markdown or HTML:
#
#   {% inject_html before:'<div class="note">' after:'</div>' %}
#   This content will be wrapped by the provided HTML.
#   {% endinject_html %}
#
# Notes:
# - The 'before' and 'after' parameters are optional; provide either or both.
# - Quotes can be single or double. Escaped quotes are supported.

require 'nokogiri'


module ReflexPlugin

 module_function

  def markdownify(text, context)
    site = context.registers[:site]
    converter = site.find_converter_instance(Jekyll::Converters::Markdown)
    converter.convert(text.to_s)
  end


  class HtmlBlock < Liquid::Block


    def initialize(tag_name, markup, tokens)
      super
      @type=parse_kv_pairs(markup)
    end

def parse_kv_pairs(str)
  kv = {}
  regex = /
    (?:
      (?<key>\w+)\s*=\s*
      (?:
        "(?<dval>(?:[^"\\]|\\.)*)" |   # double-quoted value
        '(?<sval>(?:[^'\\]|\\.)*)' |   # single-quoted value
        (?<uval>[^\s]+)                # unquoted value (no spaces)
      )
    )
  /x

  str.to_s.scan(regex) do
    m = Regexp.last_match
    key = m[:key]
    val =
      if m[:dval]
        m[:dval].gsub('\"', '"').gsub('\\n', "\n").gsub('\\\\', '\\')
      elsif m[:sval]
        m[:sval].gsub("\\'", "'").gsub('\\n', "\n").gsub('\\\\', '\\')
      else
        m[:uval]
      end
    kv[key] = val
  end

  kv
end


    def render(context)
      inner = super
      type=@type['type']
      text=@type['text']
      xpage = context.registers[:page]
      keywords = xpage['keywords'] || []
      keytext =keywords.join(", ")
      section=text.downcase
      if section=="scenario"
          type="scenario"

      end

      before= { "battlecard" => '<div class="row">
                                  <div class="col-md-2 d-none border p-3 reflex-'+text.downcase+' d-md-flex justify-content-center align-items-center">
                                   <h2 class="vertical-heading"><i class="bi bi-gear-fill me-2"></i>'+text+'</h2>
                                  </div>
                                  <div class="col-12 d-block d-md-none text-center my-3 reflex-'+text.downcase+'">
                                   <h2>'+text+'</h2>
                                  </div>
                                   <div class="col-md-10 border p-3 battlecard-detail">
                                  ',

                "scenario" => '<div class="row">
                                <div class="col-md-3 d-none border p-3 reflex-scenario d-md-flex justify-content-center align-items-center">
                                    <p class="reflex-keywords">'+keytext+'</p>
                                </div>
                                <div class="col-md-9 border p-3 battlecard-detail">
                               '
              }
      after = { "battlecard" => "</div></div>", "scenario" => "</div></div>"}


      before_html = before[type] || "<span>&#9888;</span>"
      after_html =  after[type] || "<span>&#9888;</span>"

      html = ReflexPlugin.markdownify(inner, context)

      doc  = Nokogiri::HTML.parse(html)

      "#{before_html}#{html}#{after_html}"
    end


  end
end

Liquid::Template.register_tag('block', ReflexPlugin::HtmlBlock)
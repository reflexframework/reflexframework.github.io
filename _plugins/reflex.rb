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
          @params = parse_kv_pairs(markup)
        end
def parse_args(markup)
      parts = markup.strip.split(/\s+/)
      file  = parts.shift
      params = {}

      parts.each do |p|
        k, v = p.split(":", 2)
        params[k] = v.to_s.gsub(/\A"|"\Z/, "") # strip quotes
      end

      [file, params]
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
      block_content = super
      block_content=ReflexPlugin.markdownify(block_content,context)

      site = context.registers[:site]

     icons={
        "scenario" => "bi-easel" ,
        "reconnaissance" => "bi-binoculars",
        "evaluation" => "bi-card-checklist",
        "fortify" => "bi-card-checklist",
        "limit" => "bi-stoplights",
        "expose" => "bi-alarm",
        "exercise" => "bi-bicycle"
     }

      type=@params['type']  || "<unknown>"
      text=@params['text']  || ""
      type=type.downcase
      icon_name=text.downcase

      unless icon_name.empty?
          icon_map=icons[icon_name]
         unless icon_map.nil?
             @params['icon']=icon_map
         end
      end

      tpl_path = site.in_source_dir("_includes", type+".html")

      text=@params['text'] || ""

      tpl = File.read(tpl_path)
      env = context.environments.first.merge(
              "include" => @params.merge("content" => block_content)
            )


      site.liquid_renderer
                .file(tpl_path)
                .parse(tpl)
                .render!(env, registers: context.registers)

    end


  end
end

Liquid::Template.register_tag('block', ReflexPlugin::HtmlBlock)
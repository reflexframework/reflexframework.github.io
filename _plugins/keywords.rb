
module ReflexPlugin

 module_function

class Keywords < Liquid::Tag


def unique_markdown_words(markdown)
  text = markdown.dup

  # Drop code fences and inline code
  text.gsub!(/```.*?```/m, " ")
  text.gsub!(/`[^`]*`/, " ")

  # Keep link/alt text, drop URLs
  text.gsub!(/\[([^\]]+)\]\([^)]+\)/, '\1')    # [label](url) -> label
  text.gsub!(/!\[([^\]]*)\]\([^)]+\)/, '\1')   # ![alt](url) -> alt

  # Strip HTML tags that may appear in MD
  text.gsub!(/<[^>]+>/, " ")

  # Now collect only alphanumeric words, length >= 2
  words = text.downcase.scan(/[a-z0-9]{2,}/)

  words.uniq
end

   def initialize(tag_name, text, tokens)
            super

   end

   def render(context)


        site = context.registers[:site]
        string_to_paths = Hash.new { |h, k| h[k] = [] }

        site.collections.each do | label,docs |

            docs.docs.each do | doc |
                path=doc.url
                 data=unique_markdown_words(doc.content)

               data.each do |word|
                 string_to_paths[word] << path
               end
            end


        end


        "XXX"

   end


end
end

Liquid::Template.register_tag('keywords', ReflexPlugin::Keywords)



module ReflexPlugin

 module_function

  class Icon < Liquid::Tag

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

       def initialize(tag_name, text, tokens)
            super
             @params = parse_kv_pairs(text)
             @tokens = tokens
       end

       def render(context)

            site = context.registers[:site]
            config = site.config
            icon_mapping = config['icons']
            name=@params['name']  || "bi-question"
            var = Liquid::Variable.new(name, @tokens)
            name=var.render(context) || ""
            name=name.downcase
            name=icon_mapping[name] || name


            "<i class='bi "+name+"'></i>"
       end


  end
end

Liquid::Template.register_tag('icon', ReflexPlugin::Icon)
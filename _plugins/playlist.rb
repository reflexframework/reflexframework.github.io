require "jekyll"
require 'json'
require 'deep_merge'
require 'open-uri'


module ReflexPlugin
  class GetJsonGenerator < Jekyll::Generator
    safe true
    priority :highest

    def generate(site)
      playlist_url = "https://www.youtube.com/playlist?list=PL8x_RekIw2GwwOgrtQv0jD57EgUWESjuZ"
      html = URI.open(playlist_url, "Cookie" => "CONSENT=YES+cb").read
      puts "got html"
      json_text = html[/ytInitialData\s*=\s*(\{.*?\});/, 1]
      return unless json_text
      json=JSON.parse(json_text)
      videos=json['contents']['twoColumnBrowseResultsRenderer']['tabs'][0]['tabRenderer']['content']['sectionListRenderer']['contents'][0]['itemSectionRenderer']['contents'][0]['playlistVideoListRenderer']['contents']

      playlist=[]
      site.data["playlist"]={}
      videos.each do | vid |
        entry=vid['playlistVideoRenderer']
        thumb=entry['thumbnail']['thumbnails'][0]['url']
        title=entry['title']['runs'][0]['text']
        byline=entry['shortBylineText']['runs'][0]['text']
        video={ "id" => entry['videoId'] , "title" => title , "thumb" => thumb, "byline" => byline }
        playlist << video

      end
      site.data["playlist"]['youtube']=playlist

    end
  end
end
---
layout: default
title: Youtube videos
---

 <div class="row row-cols-1 row-cols-md-2 g-4">
        {% for video in  site.data.playlist.youtube %}
         <div class="col">
            <div class="card h-100 shadow-sm ">
                <div class="card-header">
                        <h4 class="card-title">{{ video.title }} </h4>
                       {% if video.byline %}<h5 class="text-muted">{{ video.byline }}</h5>{% endif %}
               </div>
                <div class="card-body">
<iframe width="560" height="315" src="https://www.youtube.com/embed/{{video.id}}?si=Khmtb-Jnd8mntxCm" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

                </div>
            </div>
        </div>
        {% endfor %}
    </div>






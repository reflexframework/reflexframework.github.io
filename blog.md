---
layout: page
title: Blog
permalink: /blog/
---
<ul class="list-unstyled">
  {% for post in site.posts %}
    <li class="mb-3">
      <a class="fw-semibold" href="{{ post.url }}">{{ post.title }}</a><br>
      <small class="text-muted">{{ post.date | date: "%B %d, %Y" }}</small>
    </li>
  {% endfor %}
</ul>

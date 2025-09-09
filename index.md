---
layout: page
title: Make secure code second nature
subtitle: The REFLEX framework for developer-first security
---
<div class="row g-4">
  <div class="col-lg-7">
    <p>REFLEX is a practical security methodology for developers: <strong>Recon → Evaluate → Fortify → Limit → Examine → eXecute</strong>. Learn through hands-on labs, stories, and real-world demos.</p>
    <div class="row g-3">
      <div class="col-md-6">
        <a class="btn btn-primary w-100" href="/framework/">Explore the Framework</a>
      </div>
      <div class="col-md-6">
        <a class="btn btn-outline-primary w-100" href="/labs/">Run a Lab</a>
      </div>
    </div>
  </div>
  <div class="col-lg-5">
    <div class="card shadow-sm">
      <div class="card-body">
        <h2 class="h5 mb-3">What’s new</h2>
        <ul class="list-unstyled mb-0">
          {% for post in site.posts limit:4 %}
            <li class="mb-2">
              <a href="{{ post.url }}">{{ post.title }}</a>
              <small class="text-muted d-block">{{ post.date | date: "%b %d, %Y" }}</small>
            </li>
          {% endfor %}
        </ul>
      </div>
    </div>
  </div>
</div>

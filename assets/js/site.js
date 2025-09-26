
// Navbar behavior
(function(){
    var nav = document.querySelector('.nav');
    var menu = document.getElementById('nav-menu');
    var toggle = document.querySelector('.nav-toggle');

    function onScroll(){
        if(window.scrollY > 6){ nav.classList.add('scrolled'); }
        else{ nav.classList.remove('scrolled'); }
    }
    window.addEventListener('scroll', onScroll, {passive:true}); onScroll();

    // Mobile toggle
    toggle && toggle.addEventListener('click', function(){
        var open = this.getAttribute('aria-expanded') === 'true';
        this.setAttribute('aria-expanded', !open);
        menu.classList.toggle('open', !open);
    });

    // Close menu when a link is clicked (mobile UX)
    menu && menu.querySelectorAll('a').forEach(function(a){
        a.addEventListener('click', function(){
            if (window.innerWidth <= 900 && toggle){
                toggle.setAttribute('aria-expanded', 'false');
                menu.classList.remove('open');
            }
        });
    });


    const navDataEl = document.getElementById('nav-data');
    const NAV_TITLES = JSON.parse(navDataEl.textContent);




    // Active link highlight on scroll
    var sections = NAV_TITLES.map(item => document.getElementById(item)) .filter(Boolean);

    var links = Array.from(document.querySelectorAll('.nav-link'));
    function markActive(){
        var pos = window.scrollY + 100;
        var current = sections.findLast(s => s.offsetTop <= pos) || sections[0];
        links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + current.id));
    }
    window.addEventListener('scroll', markActive, {passive:true});
    window.addEventListener('load', markActive);
})();

// Playground helpers
(function(){
  const el = document.getElementById('live-clock');
  if (!el) return;
  const tick = () => { el.textContent = new Date().toLocaleString(); };
  tick();
  setInterval(tick, 1000);
})();

document.addEventListener('DOMContentLoaded', function() {
    const filterInput = document.getElementById('filterInput');
    const sections = document.querySelectorAll('[data-type="card"]');

    filterInput.addEventListener('input', function(e) {
        const filterValue = e.target.value.toLowerCase();

        sections.forEach(section => {

            const childElement = section.querySelector('.hdr-bleed');
            const keywords = childElement.textContent.toLowerCase() ;
            const isMatch = keywords.includes(filterValue);
            section.classList.toggle('hidden', !isMatch);
        });
    });
});

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

            const childElement = section.querySelector('.card-body');
            const keywords = childElement.textContent.toLowerCase() ;
            const isMatch = keywords.includes(filterValue);
            section.classList.toggle('hidden', !isMatch);
        });
    });
});

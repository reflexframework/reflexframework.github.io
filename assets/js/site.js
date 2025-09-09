// Playground helpers
(function(){
  const el = document.getElementById('live-clock');
  if (!el) return;
  const tick = () => { el.textContent = new Date().toLocaleString(); };
  tick();
  setInterval(tick, 1000);
})();

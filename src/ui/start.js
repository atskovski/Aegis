'use strict';
const form = document.getElementById('privateSearch');
const input = document.getElementById('privateSearchInput');
form.addEventListener('submit', (event) => {
  event.preventDefault();
  const q = String(input.value || '').trim();
  if (q) location.href = `aegis://app/search?q=${encodeURIComponent(q)}`;
});

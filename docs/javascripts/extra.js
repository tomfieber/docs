// Simple dynamic target replacement - with proper timing for navigation
document.addEventListener('DOMContentLoaded', function () {
  const inputElement = document.getElementById('target-input');
  if (!inputElement) return;

  function updateTargetPlaceholders() {
    const newText = inputElement.value.trim();
    const codeContainers = document.querySelectorAll('div.highlight pre code');
    
    codeContainers.forEach(container => {
      if (!container.hasAttribute('data-original-html')) {
        container.setAttribute('data-original-html', container.innerHTML);
      }
      
      const originalHTML = container.getAttribute('data-original-html');
      
      if (newText) {
        let updatedHTML = originalHTML
          .replace(/<span class="o">\{<\/span>TARGET<span class="o">\}<\/span>/g, newText)
          .replace(/{TARGET}/g, newText);
        container.innerHTML = updatedHTML;
      } else {
        container.innerHTML = originalHTML;
      }
    });
  }

  inputElement.addEventListener('input', updateTargetPlaceholders);
  
  // Use a small delay to ensure syntax highlighting is complete when navigating
  setTimeout(updateTargetPlaceholders, 100);
});

// Also handle navigation in MkDocs Material theme
if (typeof document$ !== 'undefined') {
  document$.subscribe(function() {
    setTimeout(function() {
      const inputElement = document.getElementById('target-input');
      if (!inputElement) return;

      function updateTargetPlaceholders() {
        const newText = inputElement.value.trim();
        const codeContainers = document.querySelectorAll('div.highlight pre code');
        
        codeContainers.forEach(container => {
          if (!container.hasAttribute('data-original-html')) {
            container.setAttribute('data-original-html', container.innerHTML);
          }
          
          const originalHTML = container.getAttribute('data-original-html');
          
          if (newText) {
            let updatedHTML = originalHTML
              .replace(/<span class="o">\{<\/span>TARGET<span class="o">\}<\/span>/g, newText)
              .replace(/{TARGET}/g, newText);
            container.innerHTML = updatedHTML;
          } else {
            container.innerHTML = originalHTML;
          }
        });
      }

      inputElement.addEventListener('input', updateTargetPlaceholders);
      updateTargetPlaceholders();
    }, 200);
  });
}
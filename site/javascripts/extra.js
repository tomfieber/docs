// Wait until the entire page content is loaded before running the script
document.addEventListener('DOMContentLoaded', function () {
  
  // Find our input field
  const inputElement = document.getElementById('target-input');

  // If there's no input field on this page, do nothing.
  if (!inputElement) {
    return;
  }

  // Function to find and replace {TARGET} placeholders in code blocks
  function updateTargetPlaceholders() {
    // Get the current text from the input, trimming any whitespace
    const newText = inputElement.value.trim();
    
    // Find all code blocks
    const codeContainers = document.querySelectorAll('div.highlight pre code');
    
    codeContainers.forEach(container => {
      // Store original content if not already stored
      if (!container.hasAttribute('data-original-html')) {
        container.setAttribute('data-original-html', container.innerHTML);
      }
      
      // Get the original HTML content
      const originalHTML = container.getAttribute('data-original-html');
      
      // Replace {TARGET} with the new text, or restore original if input is empty
      if (newText) {
        // Simple text replacement - replace the literal string {TARGET}
        let updatedHTML = originalHTML.replace(/{TARGET}/g, newText);
        container.innerHTML = updatedHTML;
      } else {
        container.innerHTML = originalHTML;
      }
    });
  }

  // Listen for input events (real-time updates)
  inputElement.addEventListener('input', updateTargetPlaceholders);
  
  // Run initial replacement in case there's already content in the input box
  updateTargetPlaceholders();
});
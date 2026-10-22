const status = document.getElementById('copy-status');
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const command = document.getElementById(button.dataset.copy);
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(command.textContent);
      status.textContent = 'Public example copied. Review paths and warnings before running it in your Linux terminal.';
    } catch {
      status.textContent = 'Clipboard unavailable or permission denied. Select the command text and copy it manually; nothing was run.';
      command.closest('pre').focus();
    }
  });
}

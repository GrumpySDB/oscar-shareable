document.addEventListener('DOMContentLoaded', () => {
    const accordion = document.getElementById('licensingAccordion');
    if (!accordion) return;

    const item = accordion.querySelector('.faq-item');
    const question = item.querySelector('.faq-question');

    if (!question) return;

    question.addEventListener('click', (e) => {
        e.preventDefault();
        item.classList.toggle('is-active');
    });
});

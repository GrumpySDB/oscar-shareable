document.addEventListener('DOMContentLoaded', () => {
    const faqContainer = document.getElementById('faqAccordion');
    if (!faqContainer) return;

    const faqItems = faqContainer.querySelectorAll('.faq-item');

    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        if (!question) return;

        question.addEventListener('click', (e) => {
            e.preventDefault();
            const isActive = item.classList.contains('is-active');

            // Close all other items
            faqItems.forEach(otherItem => {
                if (otherItem !== item) {
                    otherItem.classList.remove('is-active');
                }
            });

            // Toggle current item
            if (isActive) {
                item.classList.remove('is-active');
            } else {
                item.classList.add('is-active');
            }
        });
    });
});

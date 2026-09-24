/**
 * CYBERTRACE — Frontend Helper Scripts
 * Handles payload helpers, interactive tab switches, and lab triggers.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Auto-fill payload helper buttons
    const payloadButtons = document.querySelectorAll('[data-payload]');
    payloadButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetInputId = btn.getAttribute('data-target');
            const payload = btn.getAttribute('data-payload');
            const targetInput = document.getElementById(targetInputId);
            if (targetInput) {
                targetInput.value = payload;
                targetInput.focus();
            }
        });
    });

    // 2. Simple tab switcher
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            const parent = btn.closest('.tab-wrapper');
            if (parent) {
                parent.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                parent.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
                btn.classList.add('active');
                const content = parent.querySelector(`#tab-${targetTab}`);
                if (content) content.style.display = 'block';
            }
        });
    });

    // 3. Quick test fetcher for Access Control Lab
    const testAccessBtn = document.querySelectorAll('.btn-test-access');
    testAccessBtn.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const url = btn.getAttribute('data-url');
            const outputId = btn.getAttribute('data-output');
            const outputBox = document.getElementById(outputId);
            if (!outputBox) return;

            outputBox.innerHTML = '<span style="color:#00e5ff">Sending request to ' + url + '...</span>';

            try {
                const response = await fetch(url);
                if (response.status === 403) {
                    outputBox.innerHTML = '<div style="color:#f87171; font-weight:bold;">[HTTP 403 FORBIDDEN]</div>' +
                        '<div>Server-side authorization check strictly REJECTED the request.</div>' +
                        '<div style="color:#94a3b8; margin-top:4px;">Mitigation Verified: User lacks ADMIN role clearance.</div>';
                    return;
                }
                const data = await response.json();
                outputBox.innerHTML = '<pre style="color:#a7f3d0; margin-top:6px;">' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (err) {
                outputBox.innerHTML = '<span style="color:#f87171;">Request Failed: ' + err + '</span>';
            }
        });
    });
});

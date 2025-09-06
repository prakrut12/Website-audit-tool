async function startAudit() {
  const url = document.getElementById("website-url").value;
  if (!url) {
    alert("Please enter a website URL");
    return;
  }

  // Hide previous results and show loading
  document.getElementById("results-section").classList.add("hidden");
  document.getElementById("chatgpt-search-section").classList.add("hidden");
  const correctedOut = document.getElementById("corrected-output");
  if (correctedOut) correctedOut.value = "";
  const userSnippet = document.getElementById('user-snippet');
  if (userSnippet) userSnippet.value = '';
  document.getElementById("loading-section").classList.remove("hidden");

  let progress = 0;
  const progressBar = document.getElementById("progress");
  const progressText = document.getElementById("progress-text");

  // Simulated progress bar
  const interval = setInterval(() => {
    if (progress < 90) {
      progress += 10;
      progressBar.style.width = progress + "%";
      progressText.innerText = progress + "% complete";
    }
  }, 500);

  // Send request to backend
  const response = await fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url })
  });

  const data = await response.json();

  clearInterval(interval);
  progressBar.style.width = "100%";
  progressText.innerText = "100% complete";

  setTimeout(() => {
    document.getElementById("loading-section").classList.add("hidden");
    document.getElementById("results-section").classList.remove("hidden");

    // Overall score
    document.getElementById("overall-score").innerText = data.overall_score;

    // Categories
    document.getElementById("security-score").innerText = data.categories.security.score;
    document.getElementById("security-issues").innerText = data.categories.security.issues;

    document.getElementById("performance-score").innerText = data.categories.performance.score;
    document.getElementById("performance-issues").innerText = data.categories.performance.issues;
    document.getElementById("load-time").innerText = "Load time: " + data.categories.performance.load_time;

    document.getElementById("seo-score").innerText = data.categories.seo.score;
    document.getElementById("seo-issues").innerText = data.categories.seo.issues;

    document.getElementById("accessibility-score").innerText = data.categories.accessibility.score;
    document.getElementById("accessibility-issues").innerText = data.categories.accessibility.issues;

    // Populate tab contents dynamically from issues_list
    try {
      // Security tab
      const secTab = document.getElementById("tab-security");
      if (secTab && data.categories.security.issues_list) {
        const items = data.categories.security.issues_list
          .map(i => `<div class="issue-card ${i.severity || 'medium'}"><p class="issue-title">${i.title} <span class="severity ${i.severity || 'medium'}">${i.severity || ''}</span></p><p class="issue-desc">${i.desc || ''}</p></div>`)
          .join("");
        secTab.innerHTML = `<h2>🔒 Security Analysis</h2>${items || '<p>No major issues detected.</p>'}`;
      }

      // Performance tab
      const perfTab = document.getElementById("tab-performance");
      if (perfTab && data.categories.performance.issues_list) {
        const items = data.categories.performance.issues_list
          .map(i => `<div class="metric-card"><p class="metric-title">${i.title} <span class="sub-label">Issue</span></p><div class="metric-status"><span class="value">${i.desc || ''}</span><span class="status ${i.severity === 'high' ? 'poor' : 'needs-improvement'}">${i.severity || ''}</span></div></div>`)
          .join("");
        perfTab.innerHTML = `<h2>⚡ Performance Metrics</h2>${items || '<p>No major issues detected.</p>'}`;
      }

      // SEO tab
      const seoTab = document.getElementById("tab-seo");
      if (seoTab && data.categories.seo.issues_list) {
        const items = data.categories.seo.issues_list
          .map(i => `<div class="seo-card"><p class="seo-title">${i.title} <span class="impact ${i.impact || 'medium'}">${(i.impact || 'impact')}</span></p><p class="seo-desc">${i.desc || ''}</p></div>`)
          .join("");
        seoTab.innerHTML = `<h2>🔍 SEO Analysis</h2>${items || '<p>No major issues detected.</p>'}`;
      }

      // Accessibility tab
      const accTab = document.getElementById("tab-accessibility");
      if (accTab && data.categories.accessibility.issues_list) {
        const items = data.categories.accessibility.issues_list
          .map(i => `<div class="acc-card"><p class="acc-title">${i.title} <span class="wcag">WCAG ${i.wcag || ''}</span></p><p class="acc-desc">${i.desc || ''}</p></div>`)
          .join("");
        accTab.innerHTML = `<h2>👁️ Accessibility Issues</h2>${items || '<p>No major issues detected.</p>'}`;
      }
    } catch (e) {
      console.error('Failed to populate tab contents', e);
    }

    // Show ChatGPT search section after categories are displayed
    setTimeout(() => {
      document.getElementById("chatgpt-search-section").classList.remove("hidden");
      document.getElementById("generate-pdf-btn").classList.remove("hidden");
    }, 500);
  }, 1000);
}

// Function to generate PDF report
async function generatePdfReport() {
    const url = document.getElementById("website-url").value;
    if (!url) {
        alert("Please enter a website URL first.");
        return;
    }

    const generatePdfBtn = document.getElementById("generate-pdf-btn");
    if (generatePdfBtn) {
        generatePdfBtn.disabled = true;
        generatePdfBtn.innerText = "Generating PDF...";
    }

    try {
        const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url, fast: true }) // Send fast:true to get quick results
        });
        const scanData = await response.json();

        if (scanData.error) {
            alert("Error getting scan data for PDF: " + scanData.error);
            return;
        }

        const pdfResponse = await fetch("/generate_report_pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: url,
                overall_score: scanData.overall_score,
                security_score: scanData.categories.security.score,
                performance_score: scanData.categories.performance.score,
                seo_score: scanData.categories.seo.score,
                accessibility_score: scanData.categories.accessibility.score,
                security_issues_list: scanData.categories.security.issues_list,
                performance_issues_list: scanData.categories.performance.issues_list,
                seo_issues_list: scanData.categories.seo.issues_list,
                accessibility_issues_list: scanData.categories.accessibility.issues_list,
            }),
        });

        if (pdfResponse.ok) {
            const blob = await pdfResponse.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = `website_audit_report_${new Date().toISOString().slice(0,10)}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(downloadUrl);
        } else {
            const errorData = await pdfResponse.json();
            alert("Error generating PDF report: " + (errorData.error || "Unknown error"));
        }
    } catch (error) {
        console.error("Error in PDF generation process:", error);
        alert("An unexpected error occurred during PDF generation.");
    } finally {
        if (generatePdfBtn) {
            generatePdfBtn.disabled = false;
            generatePdfBtn.innerText = "Generate PDF Report";
        }
    }
}

// Add event listener to the new button
document.addEventListener('DOMContentLoaded', () => {
    const generatePdfBtn = document.getElementById('generate-pdf-btn');
    if (generatePdfBtn) {
        generatePdfBtn.addEventListener('click', generatePdfReport);
    }
});

function showTab(tab) {
  // Hide all tabs
  document.querySelectorAll(".tab-content").forEach(el => el.classList.add("hidden"));
  document.querySelectorAll(".tab-button").forEach(el => el.classList.remove("active"));

  // Show selected
  document.getElementById("tab-" + tab).classList.remove("hidden");
  event.target.classList.add("active");
}

async function sendAiFix(payload, btn) {
  const old = btn ? btn.innerText : '';
  if (btn) { btn.disabled = true; btn.innerText = 'Generating...'; }
  try {
    const res = await fetch('/ai_fix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    const out = document.getElementById('corrected-output');
    if (out) {
      out.value = data.corrected_html || '';
      out.scrollTop = 0;
    }
  } catch (e) {
    alert('Failed to generate corrected code: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.innerText = old; }
  }
}

async function generateFromUrl() {
  const notes = (document.getElementById('chatgpt-query')?.value || '').trim();
  const url = (document.getElementById('website-url')?.value || '').trim();
  if (!url) {
    alert('Enter the website URL first');
    return;
  }
  const btn = [...document.querySelectorAll('.chatgpt-search-btn')].find(b => b.textContent.includes("URL"));
  await sendAiFix({ url, notes }, btn);
}

async function generateFromSnippet() {
  const notes = (document.getElementById('chatgpt-query')?.value || '').trim();
  const html = (document.getElementById('user-snippet')?.value || '').trim();
  if (!html) {
    alert('Paste your HTML snippet first');
    return;
  }
  const btn = [...document.querySelectorAll('.chatgpt-search-btn')].find(b => b.textContent.toLowerCase().includes("snippet"));
  await sendAiFix({ html, notes }, btn);
}

// Allow Enter key to trigger search
function handleChatGPTKeyPress(event) {
  if (event.key === 'Enter') {
    generateFromUrl();
  }
}

// Toggle snippet textarea visibility based on selected mode
// No mode selector now; snippet area is always visible.

// Leaderboard
async function loadLeaderboard() {
  try {
    const section = document.getElementById('leaderboard-section');
    const list = document.getElementById('leaderboard-list');
    if (!section || !list) return;

    // Show section & skeleton while loading
    section.classList.remove('hidden');
    section.classList.remove('show');
    list.innerHTML = `
      <tr class="lb-skeleton">
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
      </tr>
      <tr class="lb-skeleton">
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
      </tr>
      <tr class="lb-skeleton">
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
        <td><div class="sk-cell"></div></td>
      </tr>
    `;

    // Fetch data
    const res = await fetch('/leaderboard');
    const data = await res.json();

    // Build rows with staggered animation and mobile data labels
    const items = (data.top || []).map((r, idx) => `
      <tr class="lb-row-appear" style="animation-delay: ${idx * 60}ms;">
        <td data-label="#">${idx + 1}</td>
        <td data-label="URL"><a href="${r.url}" target="_blank" rel="noopener">${r.url}</a></td>
        <td data-label="Security">${r.security_score}</td>
        <td data-label="Overall">${r.overall_score}</td>
      </tr>
    `).join('');

    list.innerHTML = items || '<tr><td colspan="4">No data yet</td></tr>';

    // Reveal animation
    requestAnimationFrame(() => {
      section.classList.add('show');
    });

    // Smooth scroll into view
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) {
    alert('Failed to load leaderboard');
  }
}
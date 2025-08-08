let campaignData = [];

// Fetch campaigns from backend API
async function loadCampaigns() {
  try {
    const res = await fetch("/api/campaigns");
    if (!res.ok) throw new Error(`Failed to load campaigns: ${res.statusText}`);
    campaignData = await res.json();
    renderCampaigns(campaignData);
  } catch (err) {
    console.error(err);
    document.getElementById("campaignList").innerHTML = "<p>Error loading campaigns.</p>";
  }
}

function renderCampaigns(data) {
  const campaignList = document.getElementById("campaignList");
  campaignList.innerHTML = "";

  if (data.length === 0) {
    campaignList.innerHTML += "<p>No campaigns match the filters.</p>";
    return;
  }

  data.forEach((campaign, index) => {
    const card = document.createElement("div");
    card.className = "campaign-card";
    card.innerHTML = `
      <div class="campaign-header" onclick="toggleDetails('details-${index}')">
        <h3>${campaign.name}</h3>
        <p class="campaign-description">${campaign.description}</p>
        <span class="status ${campaign.status.toLowerCase()}">${campaign.status}</span>
      </div>
      <div class="campaign-details" id="details-${index}" style="display:none;">
        <p><strong>Start:</strong> ${campaign.start_date ? new Date(campaign.start_date).toLocaleDateString() : "N/A"}</p>
        <p><strong>End:</strong> ${campaign.end_date ? new Date(campaign.end_date).toLocaleDateString() : "N/A"}</p>
        <p><strong>Click-through rate:</strong> ${campaign.click_through_rate || "0%"}</p>
        <p><strong>Targets:</strong></p>
        <ol>
          ${campaign.targets && campaign.targets.length > 0
            ? campaign.targets.map(t => `
              <li>${t.email} - ${t.clicked
                ? `Clicked at ${t.click_time || ""} on ${t.click_date || ""}`
                : "Not Clicked"}</li>
            `).join('')
            : "<li>No targets</li>"
          }
        </ol>
        <button onclick="alert('Generate report for ${campaign.name}')">View Report</button>
        <button onclick="deleteCampaign(${campaign.id})">Delete</button>
        ${campaign.status === "Ongoing" ? `<button onclick="closeCampaign(${campaign.id})">Close Campaign</button>` : ""}
      </div>
    `;
    campaignList.appendChild(card);
  });
}

async function closeCampaign(id) {
  try {
    const res = await fetch(`/close-campaign/${id}`, { method: "POST" });
    if (res.ok) {
      loadCampaigns();
    } else {
      alert("Failed to close campaign");
    }
  } catch (err) {
    console.error(err);
  }
}

function toggleDetails(id) {
  const el = document.getElementById(id);
  el.style.display = el.style.display === "none" ? "block" : "none";
}

function filterCampaigns() {
  const keyword = document.getElementById("keywordInput").value.toLowerCase();
  const startDate = document.getElementById("startDateInput").value;
  const endDate = document.getElementById("endDateInput").value;
  const status = document.getElementById("statusInput").value;
  const minTargets = parseInt(document.getElementById("minTargetsInput").value, 10) || 0;

  const filtered = campaignData.filter(campaign => {
    const matchesKeyword =
      campaign.name.toLowerCase().includes(keyword) ||
      (campaign.targets && campaign.targets.some(t => t.email.toLowerCase().includes(keyword)));

    const matchesStart = !startDate || (campaign.start_date && campaign.start_date >= startDate);
    const matchesEnd = !endDate || (campaign.end_date && campaign.end_date <= endDate);
    const matchesStatus = !status || campaign.status === status;
    const matchesTargetCount = (campaign.targets ? campaign.targets.length : 0) >= minTargets;

    return matchesKeyword && matchesStart && matchesEnd && matchesStatus && matchesTargetCount;
  });

  renderCampaigns(filtered);
}

function resetFilters() {
  document.getElementById("keywordInput").value = "";
  document.getElementById("startDateInput").value = "";
  document.getElementById("endDateInput").value = "";
  document.getElementById("statusInput").value = "";
  document.getElementById("minTargetsInput").value = "";

  renderCampaigns(campaignData);
}

// Load campaigns on page load
loadCampaigns();

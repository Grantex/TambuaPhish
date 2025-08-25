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
    campaignList.innerHTML += "<p>Launch some campaigns to see them here.</p>";
    return;
  }

  data.forEach((campaign, index) => {
    const totalRecipients = campaign.recipients ? campaign.recipients.length : 0;
    const clicks = campaign.recipients
      ? campaign.recipients.filter(r => r.has_clicked).length
      : 0;
    const clickRate = totalRecipients > 0 ? ((clicks / totalRecipients) * 100).toFixed(1) + "%" : "0%";

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
        <p><strong>Total Recipients:</strong> ${totalRecipients}</p>
        <p><strong>Clicks:</strong> ${clicks}</p>
        <p><strong>Click-through Rate:</strong> ${clickRate}</p>
        <p><strong>Recipients:</strong></p>
        <ol>
          ${
            campaign.recipients && campaign.recipients.length > 0
              ? campaign.recipients
                  .map(r => `
                    <li>
                      ${r.email} - ${
                        r.has_clicked
                          ? `Clicked at ${r.clicked_at ? new Date(r.clicked_at).toLocaleString() : ""}`
                          : "Not Clicked"
                      }
                    </li>
                  `)
                  .join("")
              : "<li>No recipients</li>"
          }
        </ol>
        <button onclick="viewReport(${campaign.id})">View Report</button>
        <button onclick="deleteCampaign(${campaign.id})">Delete</button>
        ${
          campaign.status === "Ongoing"
            ? `<button onclick="closeCampaign(${campaign.id}, '${campaign.name}')">Close Campaign</button>`
            : ""
        }
      </div>
    `;
    campaignList.appendChild(card);
  });
}

// 🟢 Redirect to the report page
function viewReport(campaignId) {
  window.location.href = `/campaign/${campaignId}/report`;
}

// Close campaign
async function closeCampaign(id) {
  if (!confirm(`Are you sure you want to close the campaign with ID ${id}?`)) return;

  const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute("content");

  try {
    const res = await fetch(`/close-campaign/${id}`, {
      method: "POST",
      headers: {
        "X-CSRFToken": csrfToken
      }
    });

    if (res.ok) {
      alert("Campaign closed successfully!");
      loadCampaigns();
    } else {
      const errorData = await res.json().catch(() => ({}));
      alert(`Failed to close campaign: ${errorData.error || res.statusText}`);
    }
  } catch (err) {
    console.error(err);
    alert("An error occurred while trying to close the campaign.");
  }
}

// Delete campaign
// Delete campaign
async function deleteCampaign(id) {
    if (!confirm(`Are you sure you want to delete campaign ID ${id}? This action cannot be undone.`)) return;

    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute("content");

    try {
        const res = await fetch(`/api/campaigns/${id}`, {
            method: "DELETE",
            headers: {
                "X-CSRFToken": csrfToken
            }
        });

        if (res.ok) {
            alert("Campaign deleted successfully!");
            loadCampaigns(); // Reload the list of campaigns
        } else {
            const errorData = await res.json().catch(() => ({}));
            alert(`Failed to delete campaign: ${errorData.error || res.statusText}`);
        }
    } catch (err) {
        console.error(err);
        alert("An error occurred while trying to delete the campaign.");
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
      (campaign.recipients &&
        campaign.recipients.some(r => r.email.toLowerCase().includes(keyword)));

    const matchesStart = !startDate || (campaign.start_date && campaign.start_date >= startDate);
    const matchesEnd = !endDate || (campaign.end_date && campaign.end_date <= endDate);
    const matchesStatus = !status || campaign.status === status;
    const matchesTargetCount = (campaign.recipients ? campaign.recipients.length : 0) >= minTargets;

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

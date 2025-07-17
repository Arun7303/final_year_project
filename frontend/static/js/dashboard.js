document.addEventListener('DOMContentLoaded', function() {
    // Audio elements
    const anomalySound = document.getElementById('anomaly-sound');
    const usbSound = document.getElementById('usb-sound');
    
    // Sound control
    let soundsAllowed = false;
    const soundToggle = document.getElementById('sound-toggle');
    
    // Initialize audio
    function initAudio() {
        anomalySound.volume = 0.3;
        usbSound.volume = 0.3;
        
        // Try to play/pause to unlock audio on mobile
        const playPromise = anomalySound.play().then(() => {
            anomalySound.pause();
        }).catch(e => console.log("Audio init error:", e));
    }
    
    // Toggle sound
    function toggleSounds() {
        soundsAllowed = !soundsAllowed;
        soundToggle.textContent = soundsAllowed ? "Disable Sounds" : "Enable Sounds";
        localStorage.setItem('soundsAllowed', soundsAllowed);
        
        if (soundsAllowed) {
            initAudio();
        }
    }
    
    // Play anomaly sound
    function playAnomalySound() {
        if (!soundsAllowed) return;
        
        try {
            anomalySound.currentTime = 0;
            anomalySound.play().catch(e => console.log("Anomaly sound play error:", e));
        } catch (e) {
            console.error("Anomaly sound error:", e);
        }
    }
    
    // Play USB sound
    function playUsbSound() {
        if (!soundsAllowed) return;
        
        try {
            usbSound.currentTime = 0;
            usbSound.play().catch(e => console.log("USB sound play error:", e));
        } catch (e) {
            console.error("USB sound error:", e);
        }
    }
    
    // Initialize
    soundToggle.addEventListener('click', toggleSounds);
    
    // Load sound preference
    soundsAllowed = localStorage.getItem('soundsAllowed') === 'true';
    soundToggle.textContent = soundsAllowed ? "Disable Sounds" : "Enable Sounds";
    if (soundsAllowed) initAudio();
    
    // Socket.IO connection
    const socket = io();
    
    // Track online users and anomaly count
    const onlineUsers = new Set();
    let anomalyCount = 0;
    
    // Update user counts display
    function updateUserCounts() {
        const totalUsers = document.querySelectorAll('.user-tile').length;
        const onlineCount = onlineUsers.size;
        const offlineCount = totalUsers - onlineCount;
        
        document.getElementById('total-count').textContent = totalUsers;
        document.getElementById('online-count').textContent = onlineCount;
        document.getElementById('offline-count').textContent = offlineCount;
        document.getElementById('anomaly-count').textContent = anomalyCount;
    }
    
    // Handle new anomaly alert
    socket.on('insider_threat_alert', function(data) {
        anomalyCount++;
        updateUserCounts();
        playAnomalySound();
        
        const container = document.getElementById('alerts-container');
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert';
        alertDiv.innerHTML = `
            <strong>${new Date().toLocaleTimeString()} - Anomaly Detected!</strong>
            <div>User: ${data.user_id}</div>
            <div>Score: ${data.score.toFixed(2)}</div>
            <button class="btn btn-sm btn-outline-info mt-2" 
                    onclick="showAnomalyDetails('${data.user_id}', ${JSON.stringify(data).replace(/"/g, '&quot;')})">
                View Details
            </button>
        `;
        container.prepend(alertDiv);
        
        // Highlight user tile
        const userTile = document.getElementById(`user-${data.user_id}`);
        if (userTile) {
            userTile.classList.add('anomaly-detected');
            setTimeout(() => {
                userTile.classList.remove('anomaly-detected');
            }, 10000);
        }
    });
    
    // Handle USB alert
    socket.on('usb_alert', function(data) {
        playUsbSound();
        
        const container = document.getElementById('usb-alerts-container');
        const alertDiv = document.createElement('div');
        alertDiv.className = 'usb-alert';
        alertDiv.textContent = data.message;
        container.appendChild(alertDiv);
        container.scrollTop = container.scrollHeight;
    });
    
    // Other socket handlers (keep your existing ones)
    socket.on('connect', () => console.log('Connected to server'));
    
    // Make functions available globally
    window.playAnomalySound = playAnomalySound;
    window.playUsbSound = playUsbSound;
    window.showAnomalyDetails = showAnomalyDetails;
    window.updateUserCounts = updateUserCounts;
});

// Global function to show anomaly details
function showAnomalyDetails(userId, data) {
    const content = document.getElementById('anomaly-details-content');
    content.innerHTML = `
        <div class="mb-3"><strong>User ID:</strong> ${userId}</div>
        <div class="mb-3"><strong>Alert Message:</strong> ${data.message}</div>
        <div class="mb-3"><strong>Anomaly Score:</strong> ${data.score.toFixed(2)}</div>
        <div class="mb-3"><strong>Reasons:</strong></div>
        <ul class="mb-3">${data.reasons.map(r => `<li>${r}</li>`).join('')}</ul>
        <div class="mb-3"><strong>Metrics:</strong></div>
        <table class="table table-sm">
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>CPU Usage</td><td>${data.metrics.cpu.toFixed(1)}%</td></tr>
                <tr><td>Memory Usage</td><td>${data.metrics.memory.toFixed(1)}%</td></tr>
                <tr><td>Network Traffic</td><td>${(data.metrics.network / 1024 / 1024).toFixed(2)} MB</td></tr>
                <tr><td>USB Connected</td><td>${data.metrics.usb ? 'Yes' : 'No'}</td></tr>
            </tbody>
        </table>
    `;
    
    const modal = new bootstrap.Modal(document.getElementById('anomalyModal'));
    modal.show();
}
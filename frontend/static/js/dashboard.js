document.addEventListener('DOMContentLoaded', function() {
    // Initialize audio elements
    const anomalySound = document.getElementById('anomaly-sound');
    const usbSound = document.getElementById('usb-sound');
    
    // Ensure sounds are properly loaded
    anomalySound.load();
    usbSound.load();
    
    // Store user interaction state
    let userInteracted = false;
    
    // Track if sounds are allowed
    let soundsAllowed = false;
    
    // Function to enable sounds after user interaction
    function enableSounds() {
        if (!userInteracted) {
            userInteracted = true;
            // Play and immediately pause to unlock audio
            anomalySound.play().then(() => {
                anomalySound.pause();
                soundsAllowed = true;
            }).catch(e => console.error("Anomaly sound init error:", e));
            
            usbSound.play().then(() => {
                usbSound.pause();
                soundsAllowed = true;
            }).catch(e => console.error("USB sound init error:", e));
        }
    }
    
    // Add click event listener to document
    document.addEventListener('click', enableSounds);
    
    // Play sound functions with improved handling
    function playAnomalySound() {
        if (!soundsAllowed) return;
        
        try {
            anomalySound.currentTime = 0;
            anomalySound.play().catch(e => console.error("Anomaly play failed:", e));
        } catch (e) {
            console.error("Anomaly sound error:", e);
        }
    }
    
    function playUsbSound() {
        if (!soundsAllowed) return;
        
        try {
            usbSound.currentTime = 0;
            usbSound.play().catch(e => console.error("USB play failed:", e));
        } catch (e) {
            console.error("USB sound error:", e);
        }
    }
    
    // Initialize socket connection
    const socket = io();
    
    // [Rest of your existing socket and dashboard code...]
    // Make sure to include all your existing functionality
    
    // Modified USB alert handler
    socket.on('usb_alert', (data) => {
        console.log("USB Alert:", data);
        playUsbSound();
        
        const container = document.getElementById('usb-alerts-container');
        const alertDiv = document.createElement('div');
        alertDiv.className = 'usb-alert';
        alertDiv.textContent = data.message;
        container.appendChild(alertDiv);
        container.scrollTop = container.scrollHeight;
    });
    
    // Modified anomaly alert handler
    socket.on('insider_threat_alert', (data) => {
        console.log("Anomaly Alert:", data);
        playAnomalySound();
        
        const container = document.getElementById('alerts-container');
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert';
        alertDiv.textContent = data.message;
        container.appendChild(alertDiv);
        container.scrollTop = container.scrollHeight;
        
        const userTile = document.getElementById(`user-${data.user_id}`);
        if (userTile) userTile.classList.add('anomaly-detected');
    });
    
    // Add a sound enable/disable toggle button to your HTML:
    // <button id="sound-toggle">Enable Sounds</button>
    const soundToggle = document.getElementById('sound-toggle');
    if (soundToggle) {
        soundToggle.addEventListener('click', function() {
            soundsAllowed = !soundsAllowed;
            this.textContent = soundsAllowed ? "Disable Sounds" : "Enable Sounds";
            if (soundsAllowed) enableSounds();
        });
    }
});
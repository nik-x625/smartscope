// Initialize sidebar functionality
function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const sidebarWrapper = document.getElementById('sidebarWrapper');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarCollapseToggle = document.getElementById('sidebarCollapseToggle');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const pageTitle = document.getElementById('pageTitle');
    
    // Function to check if we're on mobile
    function isMobile() {
        return window.innerWidth <= 768;
    }
    
    // Toggle sidebar on mobile
    if (sidebarToggle && sidebarWrapper && sidebarOverlay) {
        sidebarToggle.addEventListener('click', function() {
            if (isMobile()) {
                sidebarWrapper.classList.toggle('show');
                sidebarOverlay.classList.toggle('show');
            } else if (sidebar) {
                sidebar.classList.toggle('collapsed');
                
                // Update the toggle icon
                if (sidebarCollapseToggle) {
                    const toggleIcon = sidebarCollapseToggle.querySelector('i');
                    if (sidebar.classList.contains('collapsed')) {
                        toggleIcon.classList.remove('bi-chevron-left');
                        toggleIcon.classList.add('bi-chevron-right');
                    } else {
                        toggleIcon.classList.remove('bi-chevron-right');
                        toggleIcon.classList.add('bi-chevron-left');
                    }
                }
            }
        });
    }
    
    // Collapse sidebar from the sidebar header button
    if (sidebarCollapseToggle && sidebar) {
        sidebarCollapseToggle.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            
            // Update the toggle icon
            const toggleIcon = this.querySelector('i');
            if (sidebar.classList.contains('collapsed')) {
                toggleIcon.classList.remove('bi-chevron-left');
                toggleIcon.classList.add('bi-chevron-right');
            } else {
                toggleIcon.classList.remove('bi-chevron-right');
                toggleIcon.classList.add('bi-chevron-left');
            }
        });
    }
    
    // Close sidebar when clicking overlay
    if (sidebarOverlay && sidebarWrapper) {
        sidebarOverlay.addEventListener('click', function() {
            sidebarWrapper.classList.remove('show');
            sidebarOverlay.classList.remove('show');
        });
    }
    
    // Handle active state for menu items
    const menuButtons = document.querySelectorAll('.sidebar-menu-button');
    if (menuButtons.length > 0) {
        menuButtons.forEach(button => {
            button.addEventListener('click', function() {
                if (!this.hasAttribute('data-bs-toggle')) {
                    // Remove active class from all buttons
                    menuButtons.forEach(btn => btn.classList.remove('active'));
                    // Add active class to clicked button
                    this.classList.add('active');
                    
                    // Close sidebar on mobile when clicking a menu item
                    if (isMobile() && sidebarWrapper && sidebarOverlay) {
                        sidebarWrapper.classList.remove('show');
                        sidebarOverlay.classList.remove('show');
                    }
                }
            });
        });
    }
    
    // Handle window resize
    window.addEventListener('resize', function() {
        if (!isMobile() && sidebarOverlay && sidebarWrapper) {
            sidebarOverlay.classList.remove('show');
            sidebarWrapper.classList.remove('show');
        }
    });
}

// Initialize on DOM content loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize sidebar
    initSidebar();
    
    // Set up HTMX event handler
    if (document.body) {
        document.body.addEventListener('htmx:afterSwap', function(evt) {
            // Update active state in sidebar
            const menuButtons = document.querySelectorAll('.sidebar-menu-button');
            if (menuButtons.length > 0) {
                menuButtons.forEach(button => {
                    if (button.getAttribute('hx-get') === evt.detail.pathInfo.requestPath) {
                        button.classList.add('active');
                    } else {
                        button.classList.remove('active');
                    }
                });
            }
        });
    }
}); 
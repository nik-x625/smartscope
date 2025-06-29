function initializeSortable(element) {
    var sortableInstance = new Sortable(element, {
        animation: 150,
        ghostClass: 'sortable-ghost',
        filter: ".htmx-indicator",
        onMove: function (evt) {
            return evt.related.className.indexOf('htmx-indicator') === -1;
        },
        onStart: function(evt) {
            evt.item.classList.add('border-blue-500');
        },
        onEnd: function(evt) {
            evt.item.classList.remove('border-blue-500');
        }
    });
    return sortableInstance;
}

// Initialize on page load
htmx.onLoad(function(content) {
    var sortables = content.querySelectorAll(".sortable");
    for (var i = 0; i < sortables.length; i++) {
        initializeSortable(sortables[i]);
    }
});

// Initialize after any HTMX swap
document.body.addEventListener('htmx:afterSwap', function(evt) {
    var sortables = evt.detail.target.querySelectorAll(".sortable");
    for (var i = 0; i < sortables.length; i++) {
        initializeSortable(sortables[i]);
    }
}); 
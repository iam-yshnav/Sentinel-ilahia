// Example: Simple validation for file upload size
document.getElementById('attachment').addEventListener('change', function () {
    const file = this.files[0];
    if (file && file.size > 5 * 1024 * 1024) { // 5 MB limit
        alert('File size exceeds 5 MB');
        this.value = '';
    }
});

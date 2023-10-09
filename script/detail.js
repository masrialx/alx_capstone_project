
const titleInput = document.getElementById("titlebox");
const editButton = document.getElementById("editbtn");
const imageBox = document.getElementById('imagebox');
const imageFile = document.getElementById('imagefile');
const upload = document.getElementById('upload'); // Remove the '#' in the id selector

// Initially, hide the input border and the upload element
titleInput.style.border = "none";
upload.style.visibility = "hidden"; // Hide the 'upload' element

// Add a click event listener to the "Edit" button
editButton.addEventListener("click", function () {
    // Toggle the visibility of the 'upload' element
    if (upload.style.visibility === "hidden") {
        upload.style.visibility = "visible";
    } else {
        upload.style.visibility = "hidden";
    }

    // Check if the input border is currently hidden
    if (titleInput.style.border === "none") {
        // Show the input border
        titleInput.style.border = "1px solid #ccc";
        titleInput.removeAttribute("readonly"); // Enable editing
    } else {
        // Hide the input border
        titleInput.style.border = "none";
        titleInput.setAttribute("readonly", "true"); // Disable editing
    }
});





// Add change event listener to the file input
imageFile.addEventListener('change', () => {
    const file = imageFile.files[0]; // Get the selected file
    if (file) {
        // Create a FileReader to read the selected image file
        const reader = new FileReader();
        reader.onload = function (e) {
            // Set the image source to the selected file's data URL
            imageBox.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
});


const categorySelect = document.getElementById('categorySelect');
const options = document.getElementById('options');

// Initially, set the visibility of #options to visible and #categorySelect to hidden
options.style.display = 'block';
categorySelect.style.display = 'none';

// Add a click event listener to the "Edit" button
editButton.addEventListener('click', function () {
    if (options.style.display === 'block') {
        // Hide #options and show #categorySelect
        options.style.display = 'none';
        categorySelect.style.display = 'block';
    } else {
        // Show #options and hide #categorySelect
        options.style.display = 'block';
        categorySelect.style.display = 'none';
    }
});

const description = document.getElementById('description');

editButton.addEventListener('click', () => {
    if (description.disabled) {
        description.disabled = false;
        description.style.border = '1px solid #ccc'; // Add a border when editing
    } else {
        description.disabled = true;
        description.style.border = 'none'; // Remove the border when not editing
    }
});


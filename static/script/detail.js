const titleInput = document.getElementById("titlebox");
const editButton = document.getElementById("editbtn");
const imageBox = document.getElementById('imagebox');
const imageFile = document.getElementById('imagefile');
const upload = document.getElementById('upload');
const deleteButton = document.querySelector(".delete-button");
const popup = document.getElementById("popup");
const confirmYesButton = document.querySelector(".popup-confirm-yes");
const confirmNoButton = document.querySelector(".popup-confirm-no");
const description = document.getElementById('description');
const categorySelect = document.getElementById('categorySelect');
const options = document.getElementById('options');
const editBtn = document.getElementById("editbtn");
const saveBtn = document.getElementById("save");
const deleteBtn = document.getElementById("delete");
const closeBtn = document.getElementById("close");
const descx = document.getElementById("descx");

titleInput.style.border = "none";
upload.style.visibility = "hidden";

// Initially hide the description element and titleInput
description.style.display = "none";
titleInput.disabled = true;

// Add a click event listener to the "Edit" button
editButton.addEventListener("click", function () {
    titleInput.disabled = !titleInput.disabled;

    // Toggle the visibility of the 'upload' element
    upload.style.visibility = (upload.style.visibility === "hidden") ? "visible" : "hidden";

    // Toggle the input border
    if (titleInput.style.border === "none") {
        titleInput.style.border = "1px solid #ccc";
        titleInput.removeAttribute("readonly"); // Enable editing
    } else {
        titleInput.style.border = "none";
        titleInput.setAttribute("readonly", "true"); // Disable editing
    }

    // Toggle the visibility of the category options and categorySelect
    options.style.display = (options.style.display === 'block') ? 'none' : 'block';
    categorySelect.style.display = (categorySelect.style.display === 'block') ? 'none' : 'block';

    // Toggle the description textarea visibility
    description.style.display = (description.style.display === 'none') ? 'block' : 'none';

    // Toggle the visibility of descx
    descx.style.display = (descx.style.display === "none") ? "block" : "none";
});



// Add a click event listener to the "Edit" button
closeBtn.addEventListener("click", function () {
    titleInput.disabled = !titleInput.disabled;

    // Toggle the visibility of the 'upload' element
    upload.style.visibility = (upload.style.visibility === "hidden") ? "visible" : "hidden";

    // Toggle the input border
    if (titleInput.style.border === "none") {
        titleInput.style.border = "1px solid #ccc";
        titleInput.removeAttribute("readonly"); // Enable editing
    } else {
        titleInput.style.border = "none";
        titleInput.setAttribute("readonly", "true"); // Disable editing
    }

    // Toggle the visibility of the category options and categorySelect
    options.style.display = (options.style.display === 'block') ? 'none' : 'block';
    categorySelect.style.display = (categorySelect.style.display === 'block') ? 'none' : 'block';

    // Toggle the description textarea visibility
    description.style.display = (description.style.display === 'none') ? 'block' : 'none';

    // Toggle the visibility of descx
    descx.style.display = (descx.style.display === "none") ? "block" : "none";
});


// Add change event listener to the file input
imageFile.addEventListener('change', () => {
    const file = imageFile.files[0]; // Get the selected file
    if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            imageBox.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
});

// Show delete confirmation popup
deleteButton.addEventListener("click", () => {
    popup.style.visibility = "visible";
});

// Confirm delete action
confirmYesButton.addEventListener("click", () => {
    // Handle the delete action here (e.g., delete the post)
    console.log("Post deleted.");
    popup.style.visibility = "hidden";
});

// Cancel delete action
confirmNoButton.addEventListener("click", () => {
    popup.style.visibility = "hidden";
});

// Toggle between edit and close buttons
editBtn.addEventListener("click", function () {
    editBtn.style.display = "none";
    saveBtn.style.display = "inline-block";
    deleteBtn.style.display = "none";
    closeBtn.style.display = "inline-block";
});

closeBtn.addEventListener("click", function () {
    saveBtn.style.display = "none";
    editBtn.style.display = "inline-block";
    closeBtn.style.display = "none";
    deleteBtn.style.display = "inline-block";
});



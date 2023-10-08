// Get references to the elements
const imgList = document.getElementById('imglist');
const list = document.querySelector('.header .headers .list ul');
const headersx = document.querySelector('.header #headersx');
const listItems = document.querySelectorAll("#act li");
const loginLink = document.getElementById("login");
const categoryButtons = document.querySelectorAll('.category-button');
const descElement = document.getElementById('limitedText');

// Function to toggle the visibility of the list based on window width
function toggleVisibility() {
    if (window.innerWidth > 800) {
        list.style.visibility = 'visible';
    } else {
        list.style.visibility = 'hidden';
    }
}

// Initial check for visibility when the page loads
toggleVisibility();

// Event listener for window resize to update visibility
window.addEventListener('resize', toggleVisibility);

// Click event listener for imgList to toggle list visibility
imgList.addEventListener('click', () => {
    list.style.visibility = list.style.visibility === 'visible' ? 'hidden' : 'visible';
});

// Scroll event listener to handle header and imgList positioning
window.addEventListener('scroll', () => {
    if (window.scrollY > 100) {
        // When scrolled past 100 pixels
        headersx.style.position = 'fixed';
        headersx.style.display = 'flex';
        headersx.style.width = '100%';
        headersx.style.backgroundColor = '#07406e';
        headersx.style.justifyContent = 'space-around';
        imgList.style.position = 'absolute';
    } else {
        // When not scrolled or scrolled back up
        imgList.style.top = '15px';
        headersx.style.width = '80%';
        headersx.style.height = '10vh';
        headersx.style.display = 'flex';
        headersx.style.justifyContent = 'space-between';
        headersx.style.position = 'static';
        headersx.style.backgroundColor = 'initial';
    }
});

 
  // Add click event listeners to each button
  categoryButtons.forEach(button => {
      button.addEventListener('click', () => {
          // Remove the "active" class from all buttons
          categoryButtons.forEach(btn => btn.classList.remove('active'));

          // Add the "active" class to the clicked button
          button.classList.add('active');

          // You can perform other actions based on the selected category here
      });
  });

  
  
  document.addEventListener("DOMContentLoaded", function() {
    
    
    listItems.forEach(function(item) {
        item.addEventListener("click", function() {
            // Remove the "active" class from all list items
            listItems.forEach(function(li) {
                li.classList.remove("active");
            });

            // Add the "active" class to the clicked item
            this.classList.add("active");
            
            // Reset the background color of the "Login" link
            loginLink.style.backgroundColor = "";
        });
    });

    loginLink.addEventListener("click", function() {
        // Add the "active" class to the "Login" link
        this.classList.add("active");
        
        // Change the background color to red for the "Login" link
        this.style.backgroundColor = "red";
        
        // Remove the "active" class from all other list items
        listItems.forEach(function(li) {
            if (li !== loginLink) {
                li.classList.remove("active");
            }
        });
    });
});


  
//   const text = descElement.textContent;

//   // Split the text into words
//   const words = text.split(' ');

//   // Set the maximum number of words
//   const maxWords = 45;

//   // Create a new string with the limited number of words
//   const limitedText = words.slice(0, maxWords).join(' ');

//   // Add ellipsis (...) to the end of the limited text
//   const finalText = limitedText + '...';

//   // Replace the content of the element with the limited text with ellipsis
//   descElement.textContent = finalText;
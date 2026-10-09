
 // This gets the dark mode button from the HTML page.
const themeToggler = document.getElementById("theme-toggler");

// This loads the user's previously saved theme.
const savedTheme = localStorage.getItem("website_theme");

if (savedTheme === "dark_mode") {
    document.body.classList.add("dark_mode");
    themeToggler.textContent = "Light Mode";
}

// This changes the theme when the button is clicked.
themeToggler.addEventListener("click", function () {
    document.body.classList.toggle("dark_mode");

    // This saves the selected theme for future visits.
    if (document.body.classList.contains("dark_mode")) {
        localStorage.setItem("website_theme", "dark_mode");
        themeToggler.textContent = "Light Mode";
    } else {
        localStorage.setItem("website_theme", "default");
        themeToggler.textContent = "Dark Mode";
    }
});

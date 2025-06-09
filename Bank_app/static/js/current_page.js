function change_sidebar_color(){
    var element = document.getElementById("page-identifier");
    if (element.innerText == "Profile"){
        var sidebar_element_to_change = document.querySelector(".profile-page");
        sidebar_element_to_change.id = "current-page";
    }
    else if (element.innerText == "Finance"){
        var sidebar_element_to_change = document.querySelector(".finance-page");
        sidebar_element_to_change.id = "current-page";
    }
    else if (element.innerText == "Feedback"){
        var sidebar_element_to_change = document.querySelector(".feedback-page");
        sidebar_element_to_change.id = "current-page";
    }
    else if (element.innerText == "Blog"){
        var sidebar_element_to_change = document.querySelector(".blog-page");
        sidebar_element_to_change.id = "current-page";
    }
    else if (element.innerText == "Evidence Reconstruction Paths"){
        var sidebar_element_to_change = document.querySelector(".evirec-page");
        sidebar_element_to_change.id = "current-page";
    }
    else if (element.innerText == "Accounts"){
        var sidebar_element_to_change = document.querySelector(".users-page");
        sidebar_element_to_change.id = "current-page";
    }
    else if (element.innerText == "Roles"){
        var sidebar_element_to_change = document.querySelector(".roles-page");
        sidebar_element_to_change.id = "current-page";
    }
    else if (element.innerText == "Products"){
        var sidebar_element_to_change = document.querySelector(".products-page");
        sidebar_element_to_change.id = "current-page";
    }

}

window.onload = function() {
    change_sidebar_color();
};

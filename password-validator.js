/*
TODO add these:
    (?=.*[A-Z].*[A-Z])        Ensure string has one uppercase letter.
    (?=.*[!@#$&*])            Ensure string has one special character.
    (?=.*[0-9].*[0-9])        Ensure string has one digit.
    (?=.*[a-z].*[a-z].*[a-z]) Ensure string has one lowercase letter.
    .{8}                      Ensure string is of length 8.
*/

module.exports = (password) => {
    var result = { 
        message: null,
        valid: true
    }
    if(password == "") {
        result.message = ("Error: Password cannot be blank");
        result.valid = false;
    } else if (password.length < 8) {
        result.message = ("Error: Password has less than eight characters");
        result.valid = false;
    }
    else {
        messages = "";

        re = /[A-Z]/;
        if(!re.test(password)) {
            if(messages == "") {
                messages += "Password missing one uppercase letter";
            } else {
                messages = messages + ", " + " one uppercase letter";
            }   
        }

        re = /[a-z]/;
        if(!re.test(password)) {
            if(messages == "") {
                messages += "Password missing one lowercase letter";
            } else {
                messages = messages + ", " + " one lowercase letter";
            }   
        }

        re = /[!@#$&*^-_+=:;`~,<>?]/;
        if(!re.test(password)) {
            if(messages == "") {
                messages += "Password missing one special character";
            } else {
                messages = messages + ", " + " one special character";
            }   
        }

        re = /[0-9]/;
        if(!re.test(password)) {
            if(messages == "") {
                messages += "Password missing one digit";
            } else {
                messages = messages + ", " + " one digit";
            }   
        }

        if(!(messages == "")) {
            messages+=".";
            result.message = (messages);
            result.valid = false;
        }
    } 
    return result;
}

/*
Original:
    re = /^\w+$/;
    if(!re.test(password)) {
        result.message = ("Error: Password must contain only letters, numbers and underscores!");
        result.valid = false;
    }
    if(password.length < 12) {
        result.message = ("Error: Password must contain at least twelve characters!");
        result.valid = false;
    }
    re = /[0-9]/;
    if(!re.test(password)) {
        result.message = ("Error: password must contain at least one number (0-9)!");
        result.valid = false;
    }
    re = /[a-z]/;
    if(!re.test(password)) {
        result.message = ("Error: password must contain at least one lowercase letter (a-z)!");
        result.valid = false;
    }
    re = /[A-Z]/;
    if(!re.test(password)) {
        result.message = ("Error: password must contain at least one uppercase letter (A-Z)!");
        result.valid = false;
    }
*/
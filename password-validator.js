/*
TODO add these:
    (?=.*[A-Z].*[A-Z])        Ensure string has two uppercase letters.
    (?=.*[!@#$&*])            Ensure string has one special case letter.
    (?=.*[0-9].*[0-9])        Ensure string has two digits.
    (?=.*[a-z].*[a-z].*[a-z]) Ensure string has three lowercase letters.
    .{8}                      Ensure string is of length 8.
*/

module.exports = (password) => {
    var result = { 
        message: null,
        valid: true
    }
    if(password == "") {
        result.message = ("Error: Password cannot be blank!");
        result.valid = false;
    } 
    else {
        re = /.*[A-Z].*[A-Z]/;
        if(!re.test(password)) {
            result.message = ("Ensure password has two uppercase letters.");
            result.valid = false;
        }
        if(password.length < 12) {
            result.message = ("Ensure password contains at least twelve characters!");
            result.valid = false;
        }
        re = /.*[!@#$&*^-_+=:;`~,<>?].*[!@#$&*^-_+=:;`~,<>?]/;
        if(!re.test(password)) {
            result.message = ("Ensure password has two special case letter.");
            result.valid = false;
        }
        re = /.*[0-9].*[0-9]/;
        if(!re.test(password)) {
            result.message = ("Ensure password has two digits!");
            result.valid = false;
        }
        re = /.*[a-z].*[a-z].*[a-z]/;
        if(!re.test(password)) {
            result.message = ("Ensure password has three lowercase letters!");
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